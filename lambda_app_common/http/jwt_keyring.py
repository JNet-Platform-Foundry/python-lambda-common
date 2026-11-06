"""HS256 service-token verification with a key ring (JNET-3017).

Machine callers -- webhooks, n8n, connector adapters, tokens minted in the Admin portal --
send HS256 JWTs. Until now every one of them was signed with the single `jwt_secret` the
service configures, which is the same in every stage and cannot be revoked. Customers cannot
all be re-issued at once, so this module accepts two kinds of HS256 token side by side:

- **Legacy** (no `kid` in the header): verified against the configured `jwt_secret` exactly
  as before, and logged as `auth_type=legacy_jwt organization=<org> username=<username>` so
  the callers still on it can be found and migrated (JNET-3015). `JWT_LEGACY_ACCEPTED=false`
  turns them off -- that env var is the whole cutover.
- **Key ring** (`kid` in the header): verified against that key from the Secrets Manager
  secret named by `JWT_SIGNING_SECRET_ARN`, must carry `exp` and `jti`, and is refused if its
  `jti` is on the revocation list in the SSM parameter named by `JWT_REVOKED_PARAM`.

Contract (admin-api issues against it, infrastructure provisions it):

- `JWT_SIGNING_SECRET_ARN`: SecretString is `{"keys": [{"kid": "<stage>-<yyyymm>", "key":
  "<64 random bytes, base64url without padding>"}]}`. A list, so a rotation can hold the old
  and new key at once. Unset means this service has no ring: every `kid` token is a 401,
  legacy is unaffected.
- `JWT_REVOKED_PARAM`: an SSM String parameter holding a JSON array of revoked `jti` values
  (may be `[]`). Unset means no revocation check.
- `JWT_LEGACY_ACCEPTED`: `"true"` by default; `"false"` makes every legacy token a 401.

Failure handling is deliberately asymmetric. A ring or revocation list that cannot be read
fails closed (503) for `kid` tokens, and never touches legacy or Cognito tokens, which do not
depend on either. Nothing here logs a token, a key or the secret.

boto3 is imported only when a `kid` token first needs AWS. The Lambda runtime provides it; it
is not a dependency of this package, so a service that never sets `JWT_SIGNING_SECRET_ARN`
does not need it, and every module still imports without it.
"""

import base64
import json
import os
import time
from typing import Mapping, Optional

import jwt
from aws_lambda_powertools import Logger
from aws_lambda_powertools.event_handler.exceptions import ServiceError, UnauthorizedError

logger = Logger("JwtKeyring")

## How long a fetched key ring is trusted before it is read again.
KEYRING_TTL_SECONDS = 300
## An unknown `kid` refreshes the ring once, but no more often than this: otherwise a stream of
## tokens with made-up key ids would turn every request into a Secrets Manager call.
KEYRING_UNKNOWN_KID_REFRESH_MIN_SECONDS = 30
## How long the revocation list is trusted. Revoking a token takes effect within this window.
REVOKED_TTL_SECONDS = 60
## The contract asks for 64 random bytes. Anything under 32 (HS256's own output size) is a
## misconfigured secret, refused rather than used.
MIN_KEY_BYTES = 32

## Module scope, so a warm container reads the secret and the list once per TTL.
## {"source": arn, "keys": {kid: bytes}, "fetched_at": monotonic seconds}
_keyring_cache: dict = {}
## {"source": param name, "jtis": frozenset, "fetched_at": monotonic seconds}
_revoked_cache: dict = {}
## Lazily created boto3 clients, keyed by service name. Tests replace these with stubbed ones.
_clients: dict = {}

## Indirection so tests can move the clock without patching the `time` module for everyone.
_now = time.monotonic


def _client(service: str):
    if service not in _clients:
        import boto3  # provided by the Lambda runtime; only needed once a `kid` token arrives

        _clients[service] = boto3.client(service)
    return _clients[service]


def _aws_error_code(error: Exception) -> Optional[str]:
    """AccessDeniedException, ResourceNotFoundException... -- what an operator needs to fix
    IAM or the env var, without the message text."""
    return (getattr(error, "response", None) or {}).get("Error", {}).get("Code")


def legacy_accepted() -> bool:
    return os.environ.get("JWT_LEGACY_ACCEPTED", "true").strip().lower() != "false"


def _decode_key(encoded: str) -> bytes:
    """The HMAC key bytes from base64url. Infra writes it unpadded (86 characters for 64 bytes),
    so the `=` padding is added back; a padded value works too. Strict: a stray character makes
    the ring malformed instead of being silently dropped, and a key too short to be one of ours
    is refused. (Same alphabet as `urlsafe_b64decode`, which has no strict mode.)"""
    padded = encoded + "=" * (-len(encoded) % 4)
    key = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    if len(key) < MIN_KEY_BYTES:
        raise ValueError("a key ring key is shorter than MIN_KEY_BYTES")
    return key


def _parse_keyring(secret_string: str) -> dict:
    document = json.loads(secret_string)
    keys = {}
    for entry in document["keys"]:
        kid, key = entry["kid"], entry["key"]
        if not isinstance(kid, str) or not kid or not isinstance(key, str) or not key:
            raise ValueError("every key ring entry needs a non-empty string kid and key")
        keys[kid] = _decode_key(key)
    if not keys:
        raise ValueError("the key ring holds no keys")
    return keys


def _fetch_keyring(source: str) -> dict:
    """Read and parse the ring. Any failure is a 503: a `kid` token is never accepted unverified.

    The error is logged by type only. A boto3 error message names the secret, which is fine,
    but a JSON or base64 error could quote part of the SecretString, which is not.
    """
    try:
        secret_string = _client("secretsmanager").get_secret_value(SecretId=source)["SecretString"]
        keys = _parse_keyring(secret_string)
    ## `from None`: the error handler prints the traceback, and the cause must not ride along.
    except (KeyError, TypeError, ValueError) as e:  # ValueError covers JSON and base64 errors
        logger.error("JWT key ring secret is malformed", error_type=type(e).__name__)
        raise ServiceError(503, "Unable to verify token") from None
    except Exception as e:  # noqa: BLE001 - network, permissions, throttling, no boto3
        logger.error("Fetching the JWT key ring failed", error_type=type(e).__name__,
                     error_code=_aws_error_code(e))
        raise ServiceError(503, "Unable to verify token") from None
    entry = {"source": source, "keys": keys, "fetched_at": _now()}
    _keyring_cache.clear()
    _keyring_cache.update(entry)
    return entry


def _signing_key(kid: str) -> bytes:
    source = os.environ.get("JWT_SIGNING_SECRET_ARN", "").strip()
    if not source:
        ## This service was never given a ring, so it cannot have issued this token's key.
        raise UnauthorizedError("Invalid token.")

    entry = _keyring_cache
    fresh = False
    if (not entry or entry["source"] != source
            or _now() - entry["fetched_at"] >= KEYRING_TTL_SECONDS):
        entry, fresh = _fetch_keyring(source), True

    key = entry["keys"].get(kid)
    if key is None and not fresh and _now() - entry["fetched_at"] >= KEYRING_UNKNOWN_KID_REFRESH_MIN_SECONDS:
        ## Possibly a key added by a rotation since the ring was read: look once more.
        entry = _fetch_keyring(source)
        key = entry["keys"].get(kid)
    if key is None:
        raise UnauthorizedError("Invalid token.")
    return key


def _revoked_jtis(source: str) -> frozenset:
    entry = _revoked_cache
    if entry and entry["source"] == source and _now() - entry["fetched_at"] < REVOKED_TTL_SECONDS:
        return entry["jtis"]
    try:
        value = _client("ssm").get_parameter(Name=source)["Parameter"]["Value"]
        document = json.loads(value)
        if not isinstance(document, list) or not all(isinstance(j, str) for j in document):
            raise ValueError("the revocation list must be a JSON array of strings")
        jtis = frozenset(document)
    except (KeyError, TypeError, ValueError) as e:
        logger.error("JWT revocation list is malformed", error_type=type(e).__name__)
        raise ServiceError(503, "Unable to verify token") from None
    except Exception as e:  # noqa: BLE001 - network, permissions, throttling, no boto3
        logger.error("Fetching the JWT revocation list failed", error_type=type(e).__name__,
                     error_code=_aws_error_code(e))
        raise ServiceError(503, "Unable to verify token") from None
    _revoked_cache.clear()
    _revoked_cache.update({"source": source, "jtis": jtis, "fetched_at": _now()})
    return jtis


def _decode_keyring_token(token: str, kid) -> dict:
    if not isinstance(kid, str) or not kid:
        raise UnauthorizedError("Invalid token.")
    payload = jwt.decode(
        token,
        _signing_key(kid),
        algorithms=["HS256"],
        ## `iss` is carried (admin-api sets its own base URL) but not checked: the contract
        ## does not fix its value.
        options={"require": ["exp", "jti"]},
    )
    jti = payload["jti"]
    if not isinstance(jti, str) or not jti:
        raise UnauthorizedError("Invalid token.")

    revoked_source = os.environ.get("JWT_REVOKED_PARAM", "").strip()
    if revoked_source and jti in _revoked_jtis(revoked_source):
        raise UnauthorizedError("Token has been revoked.")

    logger.info(f"auth_type=jwt_v2 kid={kid} organization={payload.get('organization')}")
    return payload


def _decode_legacy_token(token: str, legacy_secret) -> dict:
    if not legacy_accepted():
        raise UnauthorizedError("Token is no longer accepted; request a new one.")
    payload = jwt.decode(token, legacy_secret, algorithms=["HS256"])
    logger.info(
        f"auth_type=legacy_jwt organization={payload.get('organization')} "
        f"username={payload.get('username')}"
    )
    return payload


def decode_hs256_token(token: str, header: Mapping, legacy_secret) -> dict:
    """Verify an HS256 service token and return its claims.

    `header` is the token's unverified header, already read by the caller to pick this
    verifier. A `kid` key in it -- whatever its value -- selects the key ring; its absence
    selects `legacy_secret`, the service's configured `jwt_secret`. Either way the algorithm is
    pinned to HS256 here, so a header claiming anything else cannot reach a verifier through
    this function.

    PyJWT's own errors (bad signature, expired, missing claim) propagate unchanged so callers
    map them exactly as they always have; policy refusals raise UnauthorizedError and an
    unreadable ring or revocation list raises ServiceError(503).
    """
    if header.get("alg") != "HS256":
        raise UnauthorizedError("Unsupported token algorithm")
    if "kid" in header:
        return _decode_keyring_token(token, header["kid"])
    return _decode_legacy_token(token, legacy_secret)
