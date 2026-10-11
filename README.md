# lambda_app_common

Middleware for AWS Lambda services built on [Powertools for AWS Lambda (Python)](https://docs.powertools.aws.dev/lambda/python/):

- an **API Gateway handler chain** for `APIGatewayRestResolver` — request logging with credentials redacted, error handling that publishes failures as events, identity resolution, dependency injection, response logging;
- an **event middleware** for EventBridge, SQS and SES entry points;
- **bounded telemetry**: logger keys that cannot grow with the event, an `api_request` metric whose metadata cannot break the EMF flush.

It replaces the "handler object" pattern, where every Lambda built one god-object at import time that dispatched on event shape and did all of the above in one place.

## Install

```
pip install lambda_app_common
```

Services that ship only their own source tree (dependencies come from Lambda layers) vendor the repository instead:

```
git subtree add --prefix=src/platform_common https://github.com/JNet-Platform-Foundry/python-lambda-common.git main --squash
```

and import it as `src.platform_common.lambda_app_common`. Every import inside the package is relative so both layouts work; CI checks the vendored one.

## Configure once

Call `configure` from one wiring module, before any handler module builds its app:

```python
from lambda_app_common.config import configure

configure(
    stage="dev",                                   # default: $STAGE
    application="Orders",                          # default: $APPLICATION
    jwt_secret=secret,                             # default: $JWT_SECRET (HS256 service tokens)
    cognito_user_pool_id="us-east-1_AbC123",      # default: $COGNITO_USER_POOL_ID (RS256 Bearer tokens)
    cors_origins=lambda stage: [f"https://app.{stage}.example.com"],
    feature_flag_evaluator=flags.evaluate_for,     # dict -> dict; optional
    on_invocation_start=[reset_per_invocation_state],
    role_groups={**DEFAULT_ROLE_GROUPS, "is_platform_admin": "AcmeAdmin"},  # your pool's group names
    role_aliases={"is_admin": "is_platform_admin"},  # optional: an older name kept working
)
```

`OrganizationUserContext` derives `is_platform_admin`, `is_organization_admin`, `is_organization_member`, `is_organization_seller` and `is_organization_customer` from the caller's groups. The platform-admin group defaults to `PlatformAdmin`, so an unconfigured service grants it to nobody. A role alias reads and writes its field, is accepted on construction, and is emitted beside it in the service context, the feature-flag evaluation context and the serialised model.

`on_invocation_start` hooks receive the raw event at the start of every invocation, whatever the trigger. Use them for state that must not survive into the next invocation on a warm container.

## HTTP

```python
from aws_lambda_powertools.event_handler import APIGatewayRestResolver
from lambda_app_common.factory import build_service
from lambda_app_common.http import (
    api_error_handler_for, body_data, get_cors_config, inject_organization_user_context,
    inject_services, print_request_info, response_data,
)

orders = build_service("Orders", FACTORIES_MAP).build()   # at import: a bad entry fails the cold start

app = APIGatewayRestResolver(cors=get_cors_config())
app.use(middlewares=[
    print_request_info,                     # outermost
    api_error_handler_for("orders.api"),
    inject_organization_user_context,
    inject_services({"orders_service": orders}, logger=orders.logger, metrics=orders.metrics),
    response_data,                          # innermost
])


@app.get("/orders")
def list_orders():
    service = app.context["services"]["orders_service"]    # service.context is the caller
    return body_data(service.find_all())


def proxy_handler(event, context):
    return app.resolve(event, context)
```

| Middleware                                  | Does                                                                                                                                                                                                                        |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `print_request_info`                        | One summary line per request; the redacted, truncated request under `DEBUG=1`.                                                                                                                                              |
| `api_error_handler_for(source)`             | `ServiceError`s keep their status; `ValueError`/`TypeError`/`KeyError`/`AttributeError`/`IntegrityError` → 400; anything else → 500. Each failure is published on the first `event_bus` found in `app.context['services']`. |
| `inject_organization_user_context`          | Cognito authorizer claims, else `Authorization: Bearer` (RS256 verified against the pool's JWKS, HS256 against the secret), `ApiKey`, `X-Webhook-Token`, `x-api-key`; none, invalid or expired → 401. Sets `app.context['organization_user_context']`.                                |
| `legacy_user_context(bearer_identity=...)`  | The old handler's identity rules, for endpoints whose callers depend on them. See its docstring for the four differences.                                                                                                   |
| `inject_services({...}, logger=, metrics=)` | Sets `service.context` (the caller as a dict), adds the services to `app.context['services']`, appends logger keys, records `api_request`.                                                                                  |
| `response_data`                             | Logs the response status and size; the body under `DEBUG=1`.                                                                                                                                                                |

## Events

```python
from aws_lambda_powertools.utilities.data_classes import EventBridgeEvent, event_source
from lambda_app_common.events import current_invocation, event_context


@logger.inject_lambda_context(log_event=True)
@event_context(service="Invoices", logger=service.logger, metrics=service.metrics)
@event_source(data_class=EventBridgeEvent)
def handler(event, context):
    invocation = current_invocation()       # kind, source, detail_type, organization, username, ...
```

Put it inside the logger decorator and outside any `event_source` or batch decorator, so it sees the raw event. It runs the start hooks, classifies the event, prints one summary line, appends logger keys (an EventBridge `detail` larger than `DETAIL_LOG_MAX_CHARS` is replaced by its shape), and records `api_request` when given `metrics`.

## Upgrading from 1.x

2.0 removes the 1.x modules (`Database`, `Environment`, `Events`, `Factory`, `Models`, `Repository`, `RequestContext`, `Service`, `TaskProcessor`, `imports`) and their handler objects. Use the middleware above.

## Development

```
pip install -e ".[test]" sqlalchemy
pytest
```

## Releasing

Actions → **Create Release** → Run workflow on `main`, pick `patch`, `minor` or `major`. It:

1. reads the version from `pyproject.toml` (which must match `lambda_app_common.__version__`), bumps it, and refuses a tag that already exists;
2. runs the same tests as every pull request;
3. commits `Release vX.Y.Z` to `main` with both version strings bumped, then tags it, creates the GitHub release and the `release/vX.Y.Z` branch;
4. dispatches **Publish to PyPI** on the tag. It checks the tag matches the package version, runs the tests again, builds, installs the wheel in a clean venv and imports every module, uploads to PyPI with trusted publishing (environment `pypi`), and attaches Sigstore-signed artifacts to the release. A version PyPI already has is skipped, so re-running is safe.

Nobody edits the version by hand. The version in the files is always the last release.
