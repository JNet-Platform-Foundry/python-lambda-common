"""The HS256 key ring (JNET-3017), on both places an HS256 token is verified:
`Authorization: Bearer` through `inject_organization_user_context`, and `X-Webhook-Token`
through `legacy_user_context`. Every case runs on both.

Secrets Manager and SSM are boto3 clients behind botocore's Stubber, so nothing here touches
AWS: a test queues exactly the calls it expects, and an unexpected extra call fails it.
Requests go through a real resolver behind `api_error_handler_for`, so a refusal is checked as
the status code a caller gets.
"""
import base64
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import boto3
import jwt
import pytest
from aws_lambda_powertools.event_handler import APIGatewayRestResolver
from botocore.stub import Stubber

from lambda_app_common.config import configure
from lambda_app_common.http import api_error_handler_for, inject_organization_user_context, legacy_user_context
from lambda_app_common.http import jwt_keyring as keyring
from lambda_app_common.http import middlewares

from .helpers import body_of, lambda_context, proxy_event

LEGACY_SECRET = "legacy-test-secret"
SECRET_ARN = "arn:aws:secretsmanager:us-east-1:000000000000:secret:jnet/test/jwt-signing-AbCdEf"
REVOKED_PARAM = "/jnet/test/jwt/revoked-jtis"
## Infra's kid format is <stage>-<yyyymm> (platform-infrastructure #332).
KID = "dev-202611"
KEY = os.urandom(64)
OTHER_KID = "dev-202612"
OTHER_KEY = os.urandom(64)

## Where the token goes, and the identity middleware that reads it from there.
PATHS = {
    "authorization": (lambda token: {"Authorization": f"Bearer {token}"}, inject_organization_user_context),
    "webhook": (lambda token: {"X-Webhook-Token": token}, legacy_user_context()),
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _ring(*entries):
    return json.dumps({"keys": [{"kid": kid, "key": _b64url(key)} for kid, key in entries]})


def _claims(**overrides):
    """Today's admin-api claim names, plus the new jti / iat / iss."""
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=30)
    claims = {
        "organization": "TestOrg",
        "username": "integration",
        "groups": ["OrganizationAdmin"],
        "applications": ["Organizer"],
        "created_at": now.isoformat(),
        "expires_at": exp.isoformat(),
        "exp": exp,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "iss": "https://admin.api.junctionnet.dev",
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def _v2(claims=None, kid=KID, key=KEY):
    return jwt.encode(claims or _claims(), key, algorithm="HS256", headers={"kid": kid, "typ": "JWT"})


def _legacy(**overrides):
    claims = _claims(jti=None, iat=None, iss=None, **overrides)
    return jwt.encode(claims, LEGACY_SECRET, algorithm="HS256")


class Result:
    def __init__(self, response, ctx):
        self.status = response["statusCode"]
        self.message = (body_of(response) or {}).get("message", "")
        self.ctx = ctx

    @property
    def organization(self):
        assert self.status == 200, (self.status, self.message)
        return self.ctx.organization


@pytest.fixture(params=sorted(PATHS))
def run(request):
    """`run(token)` sends the token on this path and returns a Result."""
    to_headers, identity = PATHS[request.param]

    def _run(token):
        seen = {}
        app = APIGatewayRestResolver()
        app.use(middlewares=[api_error_handler_for("things.api"), identity])

        @app.get("/things")
        def get_things():
            seen["ctx"] = app.context["organization_user_context"]
            return {}

        return Result(app.resolve(proxy_event(headers=to_headers(token)), lambda_context()), seen.get("ctx"))

    _run.path = request.param
    return _run


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(keyring, "_now", c)
    return c


@pytest.fixture(autouse=True)
def aws(monkeypatch):
    """The service's legacy secret, stubbed Secrets Manager and SSM clients, and cold caches."""
    configure(stage="dev", application="App", jwt_secret=LEGACY_SECRET)
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    ssm = boto3.client("ssm", region_name="us-east-1")
    sm_stub, ssm_stub = Stubber(sm), Stubber(ssm)
    sm_stub.activate()
    ssm_stub.activate()
    monkeypatch.setattr(keyring, "_clients", {"secretsmanager": sm, "ssm": ssm})
    monkeypatch.setattr(keyring, "_keyring_cache", {})
    monkeypatch.setattr(keyring, "_revoked_cache", {})
    monkeypatch.setenv("JWT_SIGNING_SECRET_ARN", SECRET_ARN)
    monkeypatch.delenv("JWT_REVOKED_PARAM", raising=False)
    monkeypatch.delenv("JWT_LEGACY_ACCEPTED", raising=False)
    yield sm_stub, ssm_stub
    sm_stub.deactivate()
    ssm_stub.deactivate()


def _serve_ring(sm_stub, ring=None):
    sm_stub.add_response(
        "get_secret_value",
        {"ARN": SECRET_ARN, "Name": "jnet/test/jwt-signing", "SecretString": ring or _ring((KID, KEY))},
        {"SecretId": SECRET_ARN},
    )


def _serve_revoked(ssm_stub, jtis):
    ssm_stub.add_response(
        "get_parameter",
        {"Parameter": {"Name": REVOKED_PARAM, "Type": "String", "Value": json.dumps(jtis)}},
        {"Name": REVOKED_PARAM},
    )


# --- Legacy tokens (no kid): unchanged until the cutover --------------------------------------

class TestLegacy:
    def test_accepted_by_default_without_touching_aws(self, aws, run):
        result = run(_legacy())
        assert result.organization == "TestOrg"
        aws[0].assert_no_pending_responses()  # nothing queued, nothing called

    def test_accepted_when_explicitly_true(self, run, monkeypatch):
        monkeypatch.setenv("JWT_LEGACY_ACCEPTED", "true")
        assert run(_legacy()).organization == "TestOrg"

    @pytest.mark.parametrize("value", ["false", "FALSE", " false "])
    def test_rejected_when_legacy_turned_off(self, run, monkeypatch, value):
        monkeypatch.setenv("JWT_LEGACY_ACCEPTED", value)
        assert run(_legacy()).status == 401

    def test_turning_legacy_off_does_not_affect_kid_tokens(self, aws, run, monkeypatch):
        monkeypatch.setenv("JWT_LEGACY_ACCEPTED", "false")
        _serve_ring(aws[0])
        assert run(_v2()).organization == "TestOrg"

    def test_fine_without_a_ring_configured(self, run, monkeypatch):
        monkeypatch.delenv("JWT_SIGNING_SECRET_ARN")
        assert run(_legacy()).organization == "TestOrg"

    def test_fine_when_the_ring_cannot_be_read(self, aws, run):
        aws[0].add_client_error("get_secret_value", service_error_code="AccessDeniedException")
        assert run(_v2()).status == 503
        assert run(_legacy()).organization == "TestOrg"

    def test_unaffected_by_the_revocation_list(self, aws, run, monkeypatch):
        ## A legacy token has no jti and the list is never read for it.
        monkeypatch.setenv("JWT_REVOKED_PARAM", REVOKED_PARAM)
        assert run(_legacy()).organization == "TestOrg"
        aws[1].assert_no_pending_responses()

    def test_the_secret_the_service_configures_is_the_one_used(self, run):
        configure(jwt_secret="a-different-service-secret")
        assert run(_legacy()).status == 401
        token = jwt.encode(_claims(jti=None), "a-different-service-secret", algorithm="HS256")
        assert run(token).organization == "TestOrg"

    def test_wrong_secret_still_401(self, run):
        token = jwt.encode({"organization": "TestOrg", "username": "x"}, "not-the-secret", algorithm="HS256")
        assert run(token).status == 401

    def test_expired_still_401(self, run):
        result = run(_legacy(exp=datetime.now(timezone.utc) - timedelta(hours=1)))
        assert result.status == 401 and "expired" in result.message


# --- Key ring tokens (kid) --------------------------------------------------------------------

class TestKeyring:
    def test_valid_token_gives_the_same_context_as_a_legacy_one(self, aws, run):
        ## Both claim shapes, so each path reads real groups: the Authorization path reads
        ## `groups`, the webhook path `user_groups`.
        extra = {"user_groups": ["OrganizationAdmin"], "user_applications": ["Organizer"]}
        _serve_ring(aws[0])
        new = run(_v2(_claims(**extra)))
        old = run(_legacy(**extra))
        assert new.status == old.status == 200
        assert new.ctx.as_service_context() == old.ctx.as_service_context()
        assert new.ctx.organization == "TestOrg"
        assert new.ctx.username == "integration"
        assert new.ctx.user_groups == ["OrganizationAdmin"]
        assert new.ctx.user_applications == ["Organizer"]
        assert new.ctx.is_organization_admin is True

    def test_unpadded_86_char_key_as_infra_writes_it(self, aws, run):
        ## 64 bytes as base64url without padding is 86 characters; the decoded bytes are the
        ## HMAC key, so a token signed with the raw bytes verifies.
        encoded = base64.urlsafe_b64encode(KEY).decode().rstrip("=")
        assert len(encoded) == 86 and "=" not in encoded
        _serve_ring(aws[0], json.dumps({"keys": [{"kid": KID, "key": encoded}]}))
        assert run(_v2(key=KEY)).organization == "TestOrg"

    def test_padded_base64url_keys_load_too(self, aws, run):
        padded = json.dumps({"keys": [{"kid": KID, "key": base64.urlsafe_b64encode(KEY).decode()}]})
        _serve_ring(aws[0], padded)
        assert run(_v2()).organization == "TestOrg"

    def test_second_key_in_the_ring_verifies(self, aws, run):
        _serve_ring(aws[0], _ring((KID, KEY), (OTHER_KID, OTHER_KEY)))
        assert run(_v2(kid=OTHER_KID, key=OTHER_KEY)).organization == "TestOrg"

    def test_bad_signature_is_401(self, aws, run):
        _serve_ring(aws[0])
        assert run(_v2(key=OTHER_KEY)).status == 401

    def test_signed_with_the_legacy_secret_but_carrying_a_kid_is_401(self, aws, run):
        _serve_ring(aws[0])
        assert run(_v2(key=LEGACY_SECRET.encode())).status == 401

    def test_expired_is_401(self, aws, run):
        _serve_ring(aws[0])
        result = run(_v2(_claims(exp=datetime.now(timezone.utc) - timedelta(minutes=1))))
        assert result.status == 401 and "expired" in result.message

    def test_missing_exp_is_401(self, aws, run):
        _serve_ring(aws[0])
        claims = _claims()
        del claims["exp"]
        assert run(_v2(claims)).status == 401

    def test_missing_jti_is_401(self, aws, run):
        _serve_ring(aws[0])
        assert run(_v2(_claims(jti=None))).status == 401

    @pytest.mark.parametrize("jti", ["", 12345])
    def test_unusable_jti_is_401(self, aws, run, jti):
        _serve_ring(aws[0])
        assert run(_v2(_claims(jti=jti))).status == 401

    def test_empty_kid_is_401_without_a_fetch(self, run):
        assert run(_v2(kid="")).status == 401

    def test_non_string_kid_is_401_without_a_fetch(self, run):
        ## PyJWT will not encode an int kid, so the header is built by hand.
        _, payload, signature = _v2().split(".")
        header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": 7}).encode())
        assert run(f"{header}.{payload}.{signature}").status == 401

    def test_no_ring_configured_is_401(self, run, monkeypatch):
        monkeypatch.delenv("JWT_SIGNING_SECRET_ARN")
        assert run(_v2()).status == 401

    def test_alg_none_with_a_kid_is_401(self, run):
        token = jwt.encode(_claims(), None, algorithm="none", headers={"kid": KID})
        assert run(token).status == 401

    def test_iss_is_not_checked(self, aws, run):
        _serve_ring(aws[0])
        assert run(_v2(_claims(iss="https://anything.example.com"))).organization == "TestOrg"


class TestKeyringFetch:
    def test_the_contract_timings(self):
        ## The other tests move the clock by these constants, so pin their values here.
        assert keyring.KEYRING_TTL_SECONDS == 300
        assert keyring.KEYRING_UNKNOWN_KID_REFRESH_MIN_SECONDS == 30
        assert keyring.REVOKED_TTL_SECONDS == 60
        assert keyring.MIN_KEY_BYTES == 32

    def test_fetched_once_across_calls(self, aws, run, clock):
        _serve_ring(aws[0])  # exactly one response queued: a second call would fail
        for _ in range(5):
            clock.t += 10
            assert run(_v2()).organization == "TestOrg"
        aws[0].assert_no_pending_responses()

    def test_refetched_after_the_ttl(self, aws, run, clock):
        _serve_ring(aws[0])
        assert run(_v2()).status == 200
        clock.t += keyring.KEYRING_TTL_SECONDS
        _serve_ring(aws[0])
        assert run(_v2()).status == 200
        aws[0].assert_no_pending_responses()

    def test_unknown_kid_refreshes_once_then_401(self, aws, run, clock):
        _serve_ring(aws[0])
        assert run(_v2()).status == 200  # warm
        clock.t += keyring.KEYRING_UNKNOWN_KID_REFRESH_MIN_SECONDS
        _serve_ring(aws[0])  # the one refresh
        assert run(_v2(kid="made-up", key=OTHER_KEY)).status == 401
        aws[0].assert_no_pending_responses()
        ## ...and an immediate retry does not fetch again (nothing is queued).
        assert run(_v2(kid="made-up", key=OTHER_KEY)).status == 401

    def test_unknown_kid_inside_the_window_does_not_refresh(self, aws, run, clock):
        _serve_ring(aws[0])
        assert run(_v2()).status == 200
        clock.t += keyring.KEYRING_UNKNOWN_KID_REFRESH_MIN_SECONDS - 1
        assert run(_v2(kid="made-up", key=OTHER_KEY)).status == 401  # nothing queued

    def test_unknown_kid_on_a_cold_cache_does_not_fetch_twice(self, aws, run):
        _serve_ring(aws[0])
        assert run(_v2(kid="made-up", key=OTHER_KEY)).status == 401
        aws[0].assert_no_pending_responses()

    def test_unknown_kid_refresh_picks_up_a_rotated_key(self, aws, run, clock):
        _serve_ring(aws[0])
        assert run(_v2()).status == 200
        clock.t += keyring.KEYRING_UNKNOWN_KID_REFRESH_MIN_SECONDS
        _serve_ring(aws[0], _ring((KID, KEY), (OTHER_KID, OTHER_KEY)))
        assert run(_v2(kid=OTHER_KID, key=OTHER_KEY)).organization == "TestOrg"

    def test_fetch_error_is_503_not_a_pass(self, aws, run):
        aws[0].add_client_error("get_secret_value", service_error_code="ResourceNotFoundException")
        assert run(_v2()).status == 503

    def test_fetch_error_is_not_cached(self, aws, run):
        aws[0].add_client_error("get_secret_value", service_error_code="ThrottlingException")
        assert run(_v2()).status == 503
        _serve_ring(aws[0])
        assert run(_v2()).organization == "TestOrg"

    def test_no_boto3_is_a_503_for_kid_tokens_only(self, run, monkeypatch):
        ## Outside Lambda boto3 may be missing; that must fail closed, not crash or pass.
        import builtins
        real_import = builtins.__import__

        def no_boto3(name, *args, **kwargs):
            if name == "boto3":
                raise ModuleNotFoundError("No module named 'boto3'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(keyring, "_clients", {})
        monkeypatch.setattr(builtins, "__import__", no_boto3)
        assert run(_v2()).status == 503
        assert run(_legacy()).organization == "TestOrg"

    @pytest.mark.parametrize("secret_string", [
        "not json",
        json.dumps({"keys": []}),
        json.dumps({"nokeys": True}),
        json.dumps({"keys": [{"kid": KID}]}),
        json.dumps({"keys": [{"kid": KID, "key": "!!!not-base64!!!="}]}),
        json.dumps({"keys": [{"kid": KID, "key": _b64url(os.urandom(16))}]}),  # too short
    ])
    def test_malformed_ring_is_503(self, aws, run, secret_string):
        _serve_ring(aws[0], secret_string)
        assert run(_v2()).status == 503


class TestRevocation:
    def test_revoked_jti_is_401(self, aws, run, monkeypatch):
        monkeypatch.setenv("JWT_REVOKED_PARAM", REVOKED_PARAM)
        claims = _claims()
        _serve_ring(aws[0])
        _serve_revoked(aws[1], ["something-else", claims["jti"]])
        result = run(_v2(claims))
        assert result.status == 401 and "revoked" in result.message

    def test_not_revoked_passes(self, aws, run, monkeypatch):
        monkeypatch.setenv("JWT_REVOKED_PARAM", REVOKED_PARAM)
        _serve_ring(aws[0])
        _serve_revoked(aws[1], [])
        assert run(_v2()).organization == "TestOrg"

    def test_no_param_configured_skips_the_check(self, aws, run):
        _serve_ring(aws[0])
        assert run(_v2()).organization == "TestOrg"
        aws[1].assert_no_pending_responses()

    def test_list_cached_then_reread_after_its_ttl(self, aws, run, monkeypatch, clock):
        monkeypatch.setenv("JWT_REVOKED_PARAM", REVOKED_PARAM)
        claims = _claims()
        _serve_ring(aws[0])
        _serve_revoked(aws[1], [])
        for _ in range(3):
            assert run(_v2(claims)).status == 200
        aws[1].assert_no_pending_responses()
        clock.t += keyring.REVOKED_TTL_SECONDS
        _serve_revoked(aws[1], [claims["jti"]])
        result = run(_v2(claims))
        assert result.status == 401 and "revoked" in result.message

    def test_fetch_error_is_503_not_a_pass(self, aws, run, monkeypatch):
        monkeypatch.setenv("JWT_REVOKED_PARAM", REVOKED_PARAM)
        _serve_ring(aws[0])
        aws[1].add_client_error("get_parameter", service_error_code="ParameterNotFound")
        assert run(_v2()).status == 503

    def test_fetch_error_is_not_cached(self, aws, run, monkeypatch):
        monkeypatch.setenv("JWT_REVOKED_PARAM", REVOKED_PARAM)
        _serve_ring(aws[0])
        aws[1].add_client_error("get_parameter", service_error_code="ThrottlingException")
        assert run(_v2()).status == 503
        _serve_revoked(aws[1], [])
        assert run(_v2()).organization == "TestOrg"

    @pytest.mark.parametrize("value", ["not json", '{"jti": "x"}', "[1, 2]"])
    def test_malformed_list_is_503(self, aws, run, monkeypatch, value):
        monkeypatch.setenv("JWT_REVOKED_PARAM", REVOKED_PARAM)
        _serve_ring(aws[0])
        aws[1].add_response(
            "get_parameter",
            {"Parameter": {"Name": REVOKED_PARAM, "Type": "String", "Value": value}},
            {"Name": REVOKED_PARAM},
        )
        assert run(_v2()).status == 503


# --- The inventory log lines, and nothing secret in them --------------------------------------

class TestLogging:
    """Read what reaches the logger, not stdout: Powertools binds its handler to the stdout of
    import time, which pytest's capture has already swapped by then. stdout is checked too,
    for the `print`s on the webhook path."""

    @pytest.fixture
    def logged(self, monkeypatch):
        lines = []

        class Recorder:
            def __getattr__(self, level):
                return lambda msg, *args, **kwargs: lines.append(f"{level} {msg} {args} {kwargs}")

        monkeypatch.setattr(keyring, "logger", Recorder())
        return lines

    def test_v2_line_names_kid_and_org_but_not_the_token(self, aws, run, logged, capsys):
        _serve_ring(aws[0])
        token = _v2()
        assert run(token).status == 200
        assert logged == [f"info auth_type=jwt_v2 kid={KID} organization=TestOrg () {{}}"]
        out = "\n".join(logged) + "\n".join(capsys.readouterr())
        assert token not in out
        assert token.split(".")[2] not in out  # nor the signature on its own
        assert _b64url(KEY) not in out

    def test_legacy_line_names_org_and_user_but_not_the_token(self, run, logged, capsys):
        token = _legacy()
        assert run(token).status == 200
        assert logged == ["info auth_type=legacy_jwt organization=TestOrg username=integration () {}"]
        out = "\n".join(logged) + "\n".join(capsys.readouterr())
        assert token not in out
        assert token.split(".")[2] not in out
        assert LEGACY_SECRET not in out

    def test_a_malformed_ring_does_not_log_its_contents(self, aws, run, logged, capsys):
        leaked = _b64url(KEY)
        _serve_ring(aws[0], '{"keys": [{"kid": "x", "key": "' + leaked + '"')  # truncated JSON
        assert run(_v2()).status == 503
        out, err = capsys.readouterr()
        assert logged and leaked not in "\n".join(logged) + out + err
        ## The error handler prints the 503's traceback; the parse error is not chained onto it.
        assert "ServiceError" in err and "JSONDecodeError" not in err

    def test_a_rejected_token_is_not_logged(self, aws, run, logged, capsys):
        _serve_ring(aws[0])
        token = _v2(key=OTHER_KEY)
        assert run(token).status == 401
        assert token not in "\n".join(logged) + "\n".join(capsys.readouterr())


# --- Cognito and other algorithms never reach the ring ----------------------------------------

def test_rs256_bearer_never_reads_the_ring(monkeypatch):
    called = MagicMock(side_effect=AssertionError("must not decode RS256 via the ring"))
    monkeypatch.setattr(keyring, "decode_hs256_token", called)
    monkeypatch.setattr(middlewares, "_decode_cognito_token", lambda token, header: {
        "custom:organization": "TestOrg", "sub": "s", "cognito:username": "u", "token_use": "id"})
    header = _b64url(json.dumps({"alg": "RS256", "kid": KID}).encode())
    status, ctx = _bearer_only(f"{header}.{_b64url(b'{}')}.c2ln")
    assert status == 200 and ctx.organization == "TestOrg"
    called.assert_not_called()


def test_a_non_hs256_webhook_token_keeps_its_old_refusal(monkeypatch):
    called = MagicMock(side_effect=AssertionError("must not reach the ring"))
    monkeypatch.setattr(keyring, "decode_hs256_token", called)
    header = _b64url(json.dumps({"alg": "RS256", "kid": KID}).encode())
    token = f"{header}.{_b64url(b'{}')}.c2ln"
    app = APIGatewayRestResolver()
    app.use(middlewares=[api_error_handler_for("things.api"), legacy_user_context()])
    app.get("/things")(lambda: {})
    response = app.resolve(proxy_event(headers={"X-Webhook-Token": token}), lambda_context())
    assert response["statusCode"] == 401
    assert body_of(response)["message"] == "Invalid webhook token."
    called.assert_not_called()


def _bearer_only(token):
    seen = {}
    app = APIGatewayRestResolver()
    app.use(middlewares=[api_error_handler_for("things.api"), inject_organization_user_context])

    @app.get("/things")
    def get_things():
        seen["ctx"] = app.context["organization_user_context"]
        return {}

    response = app.resolve(proxy_event(headers={"Authorization": f"Bearer {token}"}), lambda_context())
    return response["statusCode"], seen.get("ctx")
