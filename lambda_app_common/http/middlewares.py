"""The API Gateway middleware chain.

A handler module wires the chain once, in this order:

    app = APIGatewayRestResolver(cors=get_cors_config())
    app.use(middlewares=[
        print_request_info,                    # outermost: sees every request
        api_error_handler_for("orders.api"),   # turns exceptions into 400/500 + an error event
        inject_organization_user_context,      # who is calling
        inject_orders_services,                # inject_services({...}): DI + telemetry
        response_data,                         # innermost: sees the route's result
    ])

    def proxy_handler(event, context):
        return app.resolve(event, context)

The first middleware listed is the outermost, so the error handler wraps identity
resolution (a bad token becomes a 401, not a crash) and everything inside it.
"""

import base64
import inspect
import json
import time
import traceback
import urllib.request
from typing import Any, Callable, Dict, Mapping, Optional

import jwt
from aws_lambda_powertools import Logger
from aws_lambda_powertools.event_handler import APIGatewayRestResolver, CORSConfig, Response
from aws_lambda_powertools.event_handler.exceptions import (
    BadRequestError,
    InternalServerError,
    ServiceError,
    UnauthorizedError,
)
from aws_lambda_powertools.event_handler.middlewares import NextMiddleware

from .. import telemetry
from ..config import get_config, run_invocation_start_hooks
from ..models import OrganizationUserContext
from ..redaction import redact_event, redact_headers
from . import jwt_keyring

try:  # SQLAlchemy is optional: only services with a database raise its errors.
    from sqlalchemy.exc import IntegrityError
except ImportError:  # pragma: no cover - exercised only without sqlalchemy installed
    class IntegrityError(Exception):
        """Stand-in so the except clause below stays valid without SQLAlchemy."""

logger = Logger("OrganizationMiddleware")

DEFAULT_ALLOW_HEADERS = ["Content-Type", "X-Amz-Date", "Authorization", "X-Api-Key", "X-Amz-Security-Token"]

## How much of a request body a DEBUG dump prints. Upload endpoints take multi-MB base64
## bodies, and a full dump of one is a log bill, not a debugging aid.
DEBUG_BODY_MAX_CHARS = 2000


# ---------------------------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------------------------

def get_cors_config(allow_origin=None, additional_origins=None) -> CORSConfig:
    """CORSConfig for the configured origins (or the ones passed in).

    The origins are deployment-specific, so they come from `configure(cors_origins=...)`:
    a list, or a callable taking the stage. With neither configured nor passed this raises
    rather than defaulting to "*", which browsers reject alongside credentials anyway.
    """
    if allow_origin is None:
        source = get_config().cors_origins
        origins = list(source(get_config().resolved_stage()) if callable(source) else (source or []))
        if not origins:
            raise ValueError("No CORS origins: call configure(cors_origins=...) or pass allow_origin")
        allow_origin, additional_origins = origins[0], origins[1:]

    return CORSConfig(
        allow_origin=allow_origin,
        extra_origins=additional_origins,
        allow_headers=DEFAULT_ALLOW_HEADERS,
        max_age=86400,
        allow_credentials=True,
    )


# ---------------------------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------------------------

def _decoded_body(event: Mapping) -> Optional[str]:
    body = event.get("body")
    if not body:
        return None
    if event.get("isBase64Encoded"):
        try:
            body = base64.b64decode(body).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return "<undecodable base64 body>"
    return body[:DEBUG_BODY_MAX_CHARS] if isinstance(body, str) else str(body)[:DEBUG_BODY_MAX_CHARS]


def print_event_details(app: APIGatewayRestResolver) -> None:
    """One summary line per request; the full (redacted, truncated) request under DEBUG."""
    event = app.current_event.raw_event
    if not telemetry.debug_enabled():
        telemetry.print_request_summary(_service_name(app), event)
        return

    print("#" * 128)
    print(f"[REQUEST] {event.get('httpMethod')} {event.get('path')} (resource {event.get('resource')})")
    print(f"Query params: {json.dumps(event.get('queryStringParameters') or {})}")
    print(f"Headers: {json.dumps(redact_headers(event.get('headers') or {}))}")
    body = _decoded_body(event)
    if body is not None:
        print(f"Body (first {DEBUG_BODY_MAX_CHARS} chars): {body}")
    print("#" * 128)


def _service_name(app) -> Optional[str]:
    lambda_context = getattr(app, "lambda_context", None)
    return getattr(lambda_context, "function_name", None)


def print_request_info(app: APIGatewayRestResolver, next_middleware: NextMiddleware) -> Response:
    """Log the request on the way in. Credentials are fingerprinted, never printed."""
    event = app.current_event.raw_event
    if telemetry.debug_enabled():
        logger.info("Incoming request", path=app.current_event.path, request=redact_event(event))
    else:
        logger.info("Incoming request", path=app.current_event.path, method=event.get("httpMethod"),
                    resource=event.get("resource"))
    print_event_details(app)
    return next_middleware(app)


log_request_response = print_request_info


def response_data(app: APIGatewayRestResolver, next_middleware: NextMiddleware) -> Response:
    """Log the route's result on the way out: its status and size, the body only under DEBUG."""
    result = next_middleware(app)
    try:
        status = getattr(result, "status_code", None)
        body = getattr(result, "body", None)
        size = len(body) if isinstance(body, (str, bytes)) else None
        if telemetry.debug_enabled():
            logger.info("Response received", status_code=status, size=size,
                        body=body[:DEBUG_BODY_MAX_CHARS] if isinstance(body, str) else None)
        else:
            logger.info("Response received", status_code=status, size=size)
    except Exception as e:  # noqa: BLE001 - logging must not fail the request
        print("Logging response data failed:", str(e))
    return result


# ---------------------------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------------------------

## Fallback event source for the error middleware. It must be a source the platform's
## forwarding rule accepts, or the failure event is published and then discarded before it
## reaches the trail. Services should name theirs with `api_error_handler_for()`.
DEFAULT_API_ERROR_SOURCE = "workflow.api_error"


def _handle_exception(e: Exception, detail_type: str, app: APIGatewayRestResolver,
                      event_source_name: str = DEFAULT_API_ERROR_SOURCE):
    """Log the exception, and put it on the platform event trail."""
    traceback.print_exc()

    path = getattr(app.current_event, "path", "UnknownSource")
    ## The route function is the most useful "where": the first frame that is not this
    ## module or Powertools' dispatch machinery.
    frame = next(
        (f for f in inspect.trace()[::-1]
         if f.function not in {"_run_with_error_handling", "_handle_exception", "middleware"}
         and "aws_lambda_powertools" not in f.filename),
        None,
    )
    location = frame.function if frame else "unknown"
    error_message = f"{type(e).__name__}: {str(e)}"

    print(f"[{path}:{location}] {error_message}")
    _publish_error_event(app, detail_type, event_source_name, path, location, error_message)


def _publish_error_event(app, detail_type, source, path, location, error_message):
    """Put the failure on the platform event trail, not only in the log.

    The bus is reached through `app.context['services']`, which is where the DI middleware
    puts the request's services. Best-effort: this runs while an exception is already in
    flight, and a bus that is absent or itself failing must not replace the caller's real
    error. A publish failure is printed and swallowed; the original exception propagates.
    """
    try:
        services = (getattr(app, 'context', None) or {}).get('services') or {}
        bus = next(
            (getattr(svc, 'event_bus', None) for svc in services.values()
             if getattr(svc, 'event_bus', None) is not None),
            None,
        )
        if bus is None:
            print(f"[EventTrail] no event bus on app.context — '{detail_type}' not published")
            return

        bus.publish(
            source=source,
            detail_type=detail_type,
            payload={"location": location, "path": path, "error": error_message},
        )
    except Exception as publish_error:  # noqa: BLE001 - never mask the original failure
        print(f"[EventTrail] failed to publish '{detail_type}': {publish_error}")


def api_error_handler(app: APIGatewayRestResolver, next_middleware: NextMiddleware) -> Response:
    """Turn exceptions into HTTP errors: deliberate ServiceErrors pass through, bad input is a
    400, anything else a 500. Each failure is also published as an event."""
    return _run_with_error_handling(app, next_middleware, DEFAULT_API_ERROR_SOURCE)


def api_error_handler_for(event_source_name: str):
    """`api_error_handler` with the failure event published under a source you name, so a
    service's failures group with its own events on the trail."""

    def middleware(app: APIGatewayRestResolver, next_middleware: NextMiddleware) -> Response:
        return _run_with_error_handling(app, next_middleware, event_source_name)

    ## Powertools identifies middleware by name in its logs.
    middleware.__name__ = f"api_error_handler[{event_source_name}]"
    return middleware


def _run_with_error_handling(app, next_middleware, event_source_name):
    try:
        return next_middleware(app)

    except ServiceError as e:
        ## A ServiceError is a route's DELIBERATE HTTP answer (NotFoundError, BadRequestError,
        ## UnauthorizedError). Report it, but re-raise it exactly: the generic handler below
        ## would turn every 404 and every intentional 400 into a 500.
        _handle_exception(e, type(e).__name__, app, event_source_name)
        raise

    except (ValueError, TypeError, KeyError, AttributeError, IntegrityError) as e:
        _handle_exception(e, "BadRequestError", app, event_source_name)
        raise BadRequestError(str(e)) from e

    except Exception as e:
        _handle_exception(e, "Error", app, event_source_name)
        raise InternalServerError(str(e)) from e


# ---------------------------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------------------------

def normalize_to_list(value, default=None):
    """None, "", "a,b", "[a b]" (how API Gateway renders a list claim), or a list -> a list of
    strings, never None."""
    if value is None:
        return default if default is not None else []
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("[") and text.endswith("]"):
            return [item for item in text[1:-1].replace(",", " ").split() if item]
        return [item.strip() for item in text.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if item]
    return []


_normalize_to_list = normalize_to_list


def _extract_token_from_authorization_header(headers: dict) -> Optional[str]:
    """`Bearer <jwt>` or `ApiKey <key>`, per RFC 7235 / 6750; header name case-insensitive."""
    auth_header = headers.get("Authorization") or headers.get("authorization")
    if not auth_header:
        return None

    auth_lower = auth_header.lower()
    if auth_lower.startswith("bearer ") or auth_lower.startswith("apikey "):
        parts = auth_header.split(" ", 1)
        if len(parts) != 2 or not parts[1].strip():
            raise UnauthorizedError("Authorization header is malformed")
        return parts[1].strip()

    return None


## Cognito token types accepted on a Bearer header: an ID token carries the user's custom
## attributes; an access token is what a client-credentials (machine) client gets.
COGNITO_TOKEN_USES = ("id", "access")

## How long an unknown `kid` must wait before it may trigger another JWKS fetch, so tokens
## naming made-up key ids cannot turn every request into an outbound call.
JWKS_REFETCH_MIN_SECONDS = 300

## issuer -> {"keys": {kid: PyJWK}, "fetched_at": monotonic seconds}. Module scope: a warm
## container fetches its user pool's JWKS once and keeps it.
_jwks_cache: dict = {}


def _cognito_issuer() -> str:
    pool_id = get_config().resolved_cognito_user_pool_id()
    if not pool_id:
        logger.error("RS256 token received but no cognito_user_pool_id is configured")
        raise UnauthorizedError("Unable to verify token")
    region = pool_id.split("_", 1)[0]  # pool ids are "<region>_<id>"
    return f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"


def _fetch_jwks(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - fixed https URL
        return json.load(response)


def _cognito_signing_key(issuer: str, kid: Optional[str]):
    """The user pool's public key for `kid`. The JWKS is fetched once per container, plus at
    most one refetch per JWKS_REFETCH_MIN_SECONDS when an unknown key id shows up."""
    entry = _jwks_cache.get(issuer)
    stale = entry is None or (
        kid not in entry["keys"] and time.monotonic() - entry["fetched_at"] >= JWKS_REFETCH_MIN_SECONDS
    )
    if stale:
        try:
            jwks = jwt.PyJWKSet.from_dict(_fetch_jwks(f"{issuer}/.well-known/jwks.json"))
        except jwt.exceptions.PyJWKSetError as e:
            ## No loadable key, which is also what a missing `cryptography` looks like.
            logger.error("Cognito JWKS has no usable keys; is 'cryptography' installed?", error=str(e))
            raise UnauthorizedError("Unable to verify token")
        except Exception as e:  # noqa: BLE001 - network or JSON failure
            logger.error("Fetching the Cognito JWKS failed", issuer=issuer, error=str(e))
            raise ServiceError(503, "Unable to verify token")
        entry = {"keys": {key.key_id: key for key in jwks.keys}, "fetched_at": time.monotonic()}
        _jwks_cache[issuer] = entry

    key = entry["keys"].get(kid)
    if key is None:
        raise UnauthorizedError("Invalid token.")
    return key


def _decode_cognito_token(token: str, header: Mapping) -> dict:
    issuer = _cognito_issuer()
    key = _cognito_signing_key(issuer, header.get("kid"))
    payload = jwt.decode(
        token,
        key.key,  # the RSA public key itself; PyJWT < 2.9 does not accept a PyJWK here
        algorithms=["RS256"],
        issuer=issuer,
        ## A pool has several app clients, and ID and access tokens name theirs differently
        ## (`aud` vs `client_id`), so the audience is not pinned; iss + token_use are.
        options={"verify_aud": False, "require": ["exp", "iss", "token_use"]},
    )
    if payload.get("token_use") not in COGNITO_TOKEN_USES:
        raise UnauthorizedError("Invalid token.")
    return payload


def _decode_jwt_token(token: str) -> tuple:
    """Verify a JWT and return (payload, algorithm).

    - RS256: a Cognito token, verified against the configured user pool's JWKS, with `iss`
      and `token_use` checked. Claims are trusted unverified only when API Gateway's
      authorizer supplied them, which never reaches this function.
    - HS256: an internal service token. With a `kid` header it is verified against that key
      in the Secrets Manager key ring and checked against the revocation list; without one it
      is a legacy token, verified against the configured JWT secret while
      JWT_LEGACY_ACCEPTED allows it. See `jwt_keyring` (JNET-3017).

    The header only picks which verifier runs; each is pinned to its own algorithm and key.
    A missing, "none" or other alg is a 401, as is a bad signature or an expired token.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError:
        raise UnauthorizedError("Authorization token is malformed")

    alg = header.get("alg")
    try:
        if alg == "RS256":
            return _decode_cognito_token(token, header), alg
        if alg == "HS256":
            return jwt_keyring.decode_hs256_token(token, header, get_config().resolved_jwt_secret()), alg
    except jwt.ExpiredSignatureError:
        raise UnauthorizedError("Token has expired.")
    except jwt.InvalidTokenError:
        raise UnauthorizedError("Invalid token.")
    raise UnauthorizedError("Unsupported token algorithm")


def _first_present(claims: Mapping, *names: str):
    return next((claims[name] for name in names if claims.get(name) is not None), None)


def groups_and_applications(claims: Mapping) -> tuple:
    """(user_groups, user_applications) from any of the claim shapes tokens use:
    `groups` / `applications`, Cognito's `cognito:groups` / `custom:applications`, or
    `user_groups` / `user_applications`. The first one present wins."""
    groups = _first_present(claims, "groups", "cognito:groups", "user_groups")
    applications = _first_present(claims, "applications", "custom:applications", "user_applications")
    return normalize_to_list(groups), normalize_to_list(applications)


def _context_from_cognito_claims(claims: Mapping) -> OrganizationUserContext:
    config = get_config()
    groups, applications = groups_and_applications(claims)
    return OrganizationUserContext(
        organization=claims.get("custom:organization"),
        user_id=claims.get("sub"),
        ## An access token has no cognito:username, only username.
        username=claims.get("cognito:username") or claims.get("username"),
        user_email=claims.get("email", ""),
        user_groups=groups,
        branches=normalize_to_list(claims.get("custom:branches")),
        user_applications=applications,
        user_customer=claims.get("custom:customer"),
        user_seller=claims.get("custom:seller"),
        customer_id=claims.get("custom:customer"),
        seller_id=claims.get("custom:seller"),
        environment=config.resolved_stage(),
        application=config.resolved_application(),
    ).derive_roles()


def _context_from_service_token(decoded: Mapping) -> OrganizationUserContext:
    config = get_config()
    groups, applications = groups_and_applications(decoded)
    return OrganizationUserContext(
        organization=decoded.get("organization"),
        username=decoded.get("username"),
        user_id=f"{decoded.get('organization')}-{decoded.get('username')}",
        user_email=decoded.get("email", ""),
        user_groups=groups,
        branches=normalize_to_list(decoded.get("branches")),
        user_applications=applications,
        environment=config.resolved_stage(),
        application=config.resolved_application(),
    ).derive_roles()


def attach_feature_flags(user_context: OrganizationUserContext) -> None:
    """Evaluate the flags for this user with the configured evaluator, if there is one."""
    evaluator = get_config().feature_flag_evaluator
    if evaluator is None:
        return
    try:
        context = {
            'organization': user_context.organization,
            'username': user_context.username,
            'is_platform_admin': user_context.is_platform_admin or False,
            'application': user_context.application,
            'user_applications': user_context.user_applications or [],
        }
        ## Flag rules written against an older role name keep matching.
        for alias, canonical in get_config().role_aliases.items():
            if canonical in context:
                context[alias] = context[canonical]
        flags = evaluator(context)
        if flags is not None:
            user_context.with_feature_flags(flags)
    except Exception as _ff_err:  # noqa: BLE001 - flags must not fail the request
        print(f"Feature flags evaluation skipped: {_ff_err}")


def start_invocation(app: APIGatewayRestResolver) -> None:
    """Run the start-of-invocation hooks once for this request."""
    raw = app.current_event.raw_event
    if app.context.get("_invocation_started_for") is raw:
        return
    app.append_context(_invocation_started_for=raw)
    run_invocation_start_hooks(raw)


def inject_organization_user_context(app: APIGatewayRestResolver, next_middleware: NextMiddleware) -> Response:
    """
    Resolve who is calling and put it on `app.context['organization_user_context']`.

    Priority:
      1. Cognito claims -- a user authenticated by the API's Cognito authorizer; trusted
         as-is, since API Gateway has already validated the token
      2. Authorization: Bearer <jwt> (RS256) -- a Cognito JWT with no authorizer attached,
         verified against the configured user pool's JWKS
      3. Authorization: Bearer <jwt> (HS256) -- an internal service-to-service JWT
      4. Authorization: ApiKey <key>
      5. X-Webhook-Token -- deprecated; migrate to Authorization: Bearer
      6. x-api-key -- deprecated; migrate to Authorization: ApiKey

    With none of them present the request is a 401.
    """
    start_invocation(app)

    claims = app.current_event.get("requestContext", {}).get("authorizer", {}).get("claims", None)

    if claims:
        user_context = _context_from_cognito_claims(claims)
    else:
        headers = app.current_event.get("headers", {}) or {}
        token = _extract_token_from_authorization_header(headers)
        if not token:
            token = headers.get("X-Webhook-Token") or headers.get("x-webhook-token")
        if not token:
            token = headers.get("x-api-key") or headers.get("X-Api-Key")
        if not token:
            raise UnauthorizedError("No valid Authorization header found")

        decoded, alg = _decode_jwt_token(token)
        user_context = _context_from_cognito_claims(decoded) if alg == "RS256" \
            else _context_from_service_token(decoded)

    attach_feature_flags(user_context)
    app.append_context(organization_user_context=user_context)
    return next_middleware(app)


# ---------------------------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------------------------

def inject_services(services: Dict[str, Any], *, logger: Any = None, metrics: Any = None,
                    on_context: Optional[Callable[[Dict[str, Any], APIGatewayRestResolver], None]] = None,
                    name: Optional[str] = None):
    """Build the `inject_<domain>_services` middleware for a handler module.

    For every request it:
      - sets `service.context` on each service to the caller as a plain dict
        (`OrganizationUserContext.as_service_context()`), the shape services read;
      - merges the services into `app.context['services']`, where routes and the error
        middleware find them;
      - appends the request's identity and route to `logger`'s keys, and records the
        `api_request` metric on `metrics`.

    `on_context(service_context, app)` runs after the context is set, for handlers that
    also push it into nested services.
    """
    def middleware(app: APIGatewayRestResolver, next_middleware: NextMiddleware) -> Response:
        user_context = app.context.get("organization_user_context")
        service_context = user_context.as_service_context() if user_context is not None else None

        if service_context is not None:
            for service in services.values():
                try:
                    service.context = service_context
                except AttributeError:
                    pass
            if on_context is not None:
                on_context(service_context, app)

        existing = app.context.get("services") or {}
        app.append_context(services={**existing, **services})

        stage = get_config().resolved_stage()
        event = app.current_event.raw_event
        metadata = telemetry.http_logger_metadata(event, user_context, stage)
        telemetry.append_logger_keys(logger, metadata)
        telemetry.record_api_request(
            metrics,
            telemetry.metrics_dimensions(stage, metadata.get("organization"), event.get("httpMethod")),
            metadata,
        )
        return next_middleware(app)

    middleware.__name__ = name or f"inject_services[{','.join(services)}]"
    return middleware
