"""Identity resolution exactly as the retired Lambda handler object did it.

`inject_organization_user_context` is the standard. This exists for endpoints whose callers
were built against the old rules and that are not behind a Cognito authorizer -- webhooks,
anonymous public endpoints, integrations that send an opaque `Authorization: Bearer` -- where
switching rules would lock existing callers out. It differs from the standard in four ways,
all deliberate, all inherited:

- `X-Webhook-Token` is an HS256 JWT whose groups are read from `user_groups` (default
  `["Member"]`) and applications from `user_applications`. It is verified like any HS256
  token: against the key ring when it carries a `kid`, else against the configured secret
  (see `jwt_keyring`).
- An `Authorization: Bearer ...` with no authorizer context is NOT verified. The request
  gets the fixed `bearer_identity` the service configures, or a 401 if it configures none.
- With Cognito claims, the email is read from `cognito:email` and a missing organization
  becomes `"unknown"`.
- An authorizer context without a Cognito username (client credentials) carries no user;
  the old handler crashed building the user dict, this answers 401.

Use it in the identity slot of the chain, in place of `inject_organization_user_context`.
It sets the same `app.context['organization_user_context']`, so everything after it in the
chain is unchanged. The raw bearer token is on `app.context['legacy_auth'].auth_token` for
the endpoints that validate it themselves.
"""

from dataclasses import dataclass
from typing import Any, Mapping, Optional

import jwt
from aws_lambda_powertools.event_handler import APIGatewayRestResolver, Response
from aws_lambda_powertools.event_handler.exceptions import UnauthorizedError
from aws_lambda_powertools.event_handler.middlewares import NextMiddleware

from ..config import get_config
from ..models import OrganizationUserContext
from ..redaction import redact_headers, redact_mapping, token_fingerprint
from . import jwt_keyring
from .middlewares import attach_feature_flags, normalize_to_list, start_invocation


@dataclass
class LegacyAuth:
    """What the old handler kept about the request's credentials."""
    auth_token: Optional[str] = None
    mode: str = "none"  # webhook | bearer | cognito | client_credentials | none
    scopes: Any = None
    token_use: Any = None
    client_id: Any = None


def _claim_list(value) -> list:
    """API Gateway hands a REST authorizer's list claims over as one string ("a,b" or "[a b]").

    The old handler kept that string and tested membership with `in`, i.e. by substring.
    Splitting it gives the same answer for every real group name, as a list.
    """
    return normalize_to_list(value)


def _bearer_token(headers: Mapping) -> Optional[str]:
    try:
        return headers.get("Authorization", '').split(' ')[1]
    except Exception:  # noqa: BLE001 - the old handler treated any malformed header as "no token"
        return None


def resolve_legacy_user_context(event: Mapping, bearer_identity: Optional[Mapping] = None):
    """Return `(OrganizationUserContext, LegacyAuth)` for an API Gateway proxy event.

    Raises UnauthorizedError exactly where the old handler did, plus the client-credentials
    case it used to crash on.
    """
    config = get_config()
    stage = config.resolved_stage()
    application = config.resolved_application()
    authorizer = (event.get("requestContext") or {}).get("authorizer") or {}
    headers = event.get("headers") or {}
    auth = LegacyAuth(auth_token=_bearer_token(headers))

    print("Headers:", redact_headers(headers))
    print(f"validate_request_auth.token: {token_fingerprint(auth.auth_token)}")

    webhook_token = headers.get("X-Webhook-Token")
    if webhook_token is None:
        webhook_token = headers.get("x-webhook-token")

    if not authorizer:
        if webhook_token is not None:
            try:
                header = jwt.get_unverified_header(webhook_token)
                if header.get("alg") != "HS256":
                    ## Was refused by `algorithms=["HS256"]` with this message; keep it.
                    raise UnauthorizedError("Invalid webhook token.")
                decoded = jwt_keyring.decode_hs256_token(webhook_token, header, config.resolved_jwt_secret())
            except jwt.ExpiredSignatureError:
                raise UnauthorizedError("Webhook token has expired.")
            except jwt.InvalidTokenError:
                raise UnauthorizedError("Invalid webhook token.")
            print("Webhook Token Decoded:", redact_mapping(decoded))
            auth.mode = "webhook"
            user = OrganizationUserContext(
                organization=decoded.get("organization"),
                username=decoded.get("username"),
                user_email=decoded.get("email", ""),
                user_groups=list(decoded.get("user_groups", ['Member']) or []),
                user_applications=list(decoded.get("user_applications", []) or []),
                environment=stage,
                application=application,
            )
        elif headers.get("Authorization", "").startswith("Bearer "):
            if bearer_identity is None:
                raise UnauthorizedError("Unauthorized request. No authorization context found.")
            auth.mode = "bearer"
            user = OrganizationUserContext(
                organization=bearer_identity.get("organization"),
                username=bearer_identity.get("username"),
                user_email=bearer_identity.get("email", ""),
                user_groups=list(bearer_identity.get("user_groups", ['Member'])),
                user_applications=list(bearer_identity.get("user_applications", [])),
                environment=stage,
                application=application,
            )
        else:
            print("===>>> Warning: No authorization context found in the event. <<=====")
            raise UnauthorizedError("Unauthorized request. No authorization context found.")

    elif (authorizer.get("claims") or {}).get("cognito:username") is not None:
        claims = authorizer.get("claims") or {}
        auth.mode = "cognito"
        user = OrganizationUserContext(
            organization=claims.get("custom:organization", 'unknown'),
            username=claims.get("cognito:username"),
            user_id=claims.get("sub"),
            user_email=claims.get("cognito:email"),
            user_groups=_claim_list(claims.get("cognito:groups")),
            user_applications=_claim_list(claims.get("cognito:applications")),
            user_customer=claims.get("custom:customer"),
            user_seller=claims.get("custom:seller"),
            customer_id=claims.get("custom:customer"),
            seller_id=claims.get("custom:seller"),
            environment=stage,
            application=application,
        )
    else:
        claims = (event.get("requestContext") or {}).get("claims") or {}
        auth.mode = "client_credentials"
        auth.scopes = claims.get("scope")
        auth.token_use = claims.get("token_use")
        auth.client_id = claims.get("client_id")
        raise UnauthorizedError("Unauthorized request. No user in the authorization context.")

    return user.derive_roles(), auth


def legacy_user_context(bearer_identity: Optional[Mapping] = None, name: str = "legacy_user_context"):
    """Build the identity middleware that follows the old handler's rules.

    `bearer_identity` is who an unverified `Authorization: Bearer` caller is treated as,
    e.g. `{"organization": "Acme", "username": "platform"}`. Leave it None to refuse them.
    """
    def middleware(app: APIGatewayRestResolver, next_middleware: NextMiddleware) -> Response:
        start_invocation(app)
        user_context, auth = resolve_legacy_user_context(app.current_event.raw_event, bearer_identity)
        attach_feature_flags(user_context)
        app.append_context(organization_user_context=user_context, legacy_auth=auth)
        return next_middleware(app)

    middleware.__name__ = name
    return middleware
