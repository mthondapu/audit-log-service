"""Tests for Bearer API-key authentication (D4)."""

import hashlib
import hmac
import logging
from collections.abc import Mapping

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from audit_log_service.config.api_keys import ApiKeyConfiguration, ConfiguredPrincipal
from audit_log_service.security.authentication import (
    AuthenticationError,
    authenticate,
    authenticate_api_key,
)
from audit_log_service.security.capabilities import ROLE_CAPABILITIES, Capability, Role


def test_valid_bearer_key_authenticates(
    api_key_configuration: ApiKeyConfiguration, fake_keys: Mapping[str, str]
) -> None:
    principal = authenticate([f"Bearer {fake_keys['writer']}"], api_key_configuration)

    assert principal.id == "svc-writer"
    assert principal.role is Role.WRITER
    assert principal.capabilities == frozenset({Capability.EVENTS_WRITE})


def test_every_configured_key_of_a_principal_authenticates(
    api_key_configuration: ApiKeyConfiguration, fake_keys: Mapping[str, str]
) -> None:
    for key_name in ("administrator", "administrator-rotated"):
        principal = authenticate([f"Bearer {fake_keys[key_name]}"], api_key_configuration)
        assert principal.id == "ops.admin"


@pytest.mark.parametrize("scheme", ["bearer", "BEARER", "BeArEr"])
def test_scheme_is_case_insensitive(
    api_key_configuration: ApiKeyConfiguration, fake_keys: Mapping[str, str], scheme: str
) -> None:
    principal = authenticate([f"{scheme} {fake_keys['auditor']}"], api_key_configuration)
    assert principal.id == "auditor-1"


@pytest.mark.parametrize(
    "template",
    [
        pytest.param("Bearer\t{key}", id="tab-separator"),
        pytest.param("Bearer  {key}", id="multiple-spaces"),
        pytest.param(" Bearer {key}", id="leading-space"),
        pytest.param("\tBearer {key}", id="leading-tab"),
        pytest.param("Bearer {key} ", id="trailing-space"),
        pytest.param("Bearer {key}\n", id="trailing-newline"),
        pytest.param("Bearer {key} extra", id="whitespace-inside-token"),
        pytest.param("Bearer {key}\textra", id="tab-inside-token"),
    ],
)
def test_malformed_header_around_a_valid_key_is_rejected(
    api_key_configuration: ApiKeyConfiguration, fake_keys: Mapping[str, str], template: str
) -> None:
    header = template.format(key=fake_keys["writer"])
    with pytest.raises(AuthenticationError) as caught:
        authenticate([header], api_key_configuration)
    assert caught.value.args == ()


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param([], id="missing-header"),
        pytest.param(["Basic dXNlcjpwYXNz"], id="non-bearer-scheme"),
        pytest.param(["Bearer"], id="bearer-without-token"),
        pytest.param(["Bearer "], id="bearer-with-empty-token"),
        pytest.param(["Bearer  "], id="bearer-with-whitespace-token"),
        pytest.param([""], id="empty-header"),
        pytest.param(["Bearer a b"], id="token-with-space"),
        pytest.param(["BearerX test-only-writer-key"], id="scheme-with-suffix"),
        pytest.param(["test-only-writer-key"], id="token-without-scheme"),
        pytest.param(["Bearer unknown-test-key"], id="unknown-key"),
    ],
)
def test_authentication_failures_raise_the_same_error(
    api_key_configuration: ApiKeyConfiguration, headers: list[str]
) -> None:
    with pytest.raises(AuthenticationError) as caught:
        authenticate(headers, api_key_configuration)
    assert caught.value.args == ()


def test_multiple_authorization_headers_fail_even_if_one_is_valid(
    api_key_configuration: ApiKeyConfiguration, fake_keys: Mapping[str, str]
) -> None:
    headers = [f"Bearer {fake_keys['writer']}", f"Bearer {fake_keys['auditor']}"]
    with pytest.raises(AuthenticationError):
        authenticate(headers, api_key_configuration)


def test_raw_key_is_not_accepted_as_its_own_hash(
    api_key_configuration: ApiKeyConfiguration,
) -> None:
    configured_hex = api_key_configuration.principals[0].key_digests[0].hex()
    with pytest.raises(AuthenticationError):
        authenticate([f"Bearer {configured_hex}"], api_key_configuration)


def test_comparison_is_constant_time_against_every_configured_digest(
    api_key_configuration: ApiKeyConfiguration,
    fake_keys: Mapping[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    real_compare = hmac.compare_digest

    def counting_compare(left: bytes, right: bytes) -> bool:
        calls.append(1)
        return real_compare(left, right)

    monkeypatch.setattr(hmac, "compare_digest", counting_compare)
    total_digests = sum(len(p.key_digests) for p in api_key_configuration.principals)

    authenticate([f"Bearer {fake_keys['writer']}"], api_key_configuration)
    assert len(calls) == total_digests

    calls.clear()
    with pytest.raises(AuthenticationError):
        authenticate(["Bearer unknown-test-key"], api_key_configuration)
    assert len(calls) == total_digests


def test_authentication_does_not_log_credentials(
    api_key_configuration: ApiKeyConfiguration,
    fake_keys: Mapping[str, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    authenticate([f"Bearer {fake_keys['writer']}"], api_key_configuration)
    with pytest.raises(AuthenticationError):
        authenticate(["Bearer unknown-test-key"], api_key_configuration)

    logged = caplog.text
    assert fake_keys["writer"] not in logged
    assert "unknown-test-key" not in logged
    assert "Authorization" not in logged


# Categories Z and C exclude every character `\S` rejects, so each token is well-formed and
# reaches the digest comparison against a non-empty configuration.
@given(token=st.text(alphabet=st.characters(blacklist_categories=("Z", "C")), min_size=1))
def test_arbitrary_unconfigured_tokens_never_authenticate(token: str) -> None:
    # Obviously fake keys, built inside the test rather than in a function-scoped fixture.
    writer_key = "test-only-property-writer-key"
    admin_key = "test-only-property-admin-key"
    configuration = ApiKeyConfiguration(
        principals=(
            ConfiguredPrincipal(
                id="property-writer",
                role=Role.WRITER,
                capabilities=ROLE_CAPABILITIES[Role.WRITER],
                key_digests=(hashlib.sha256(writer_key.encode()).digest(),),
            ),
            ConfiguredPrincipal(
                id="property-admin",
                role=Role.ADMINISTRATOR,
                capabilities=ROLE_CAPABILITIES[Role.ADMINISTRATOR],
                key_digests=(hashlib.sha256(admin_key.encode()).digest(),),
            ),
        )
    )
    # The configuration is live: its own keys authenticate.
    assert authenticate([f"Bearer {writer_key}"], configuration).id == "property-writer"
    assert authenticate([f"Bearer {admin_key}"], configuration).id == "property-admin"

    assume(token not in (writer_key, admin_key))
    with pytest.raises(AuthenticationError):
        authenticate([f"Bearer {token}"], configuration)


def test_raw_api_key_authenticates_the_same_principal(
    api_key_configuration: ApiKeyConfiguration, fake_keys: Mapping[str, str]
) -> None:
    # The checkpoint CLI presents the raw key, not an Authorization header (CP3).
    for name, principal_id in (("administrator", "ops.admin"), ("writer", "svc-writer")):
        from_header = authenticate([f"Bearer {fake_keys[name]}"], api_key_configuration)
        raw = authenticate_api_key(fake_keys[name], api_key_configuration)
        assert raw == from_header
        assert raw.id == principal_id


@pytest.mark.parametrize(
    "token",
    [
        "",
        " ",
        "Bearer test-only-administrator-key",
        "test-only-administrator-key ",
        " test-only-administrator-key",
        "test-only-administrator-key\n",
        "test-only\tkey",
    ],
    ids=["empty", "space", "with-scheme", "trailing-space", "leading-space", "newline", "tab"],
)
def test_raw_api_key_must_be_a_bare_token(
    api_key_configuration: ApiKeyConfiguration, token: str
) -> None:
    with pytest.raises(AuthenticationError):
        authenticate_api_key(token, api_key_configuration)


def test_raw_api_key_with_an_unpaired_surrogate_fails_authentication(
    api_key_configuration: ApiKeyConfiguration,
) -> None:
    with pytest.raises(AuthenticationError) as caught:
        authenticate_api_key("key-" + chr(0xD800), api_key_configuration)
    assert caught.value.__cause__ is None


def test_raw_api_key_compares_against_every_configured_digest(
    api_key_configuration: ApiKeyConfiguration,
    fake_keys: Mapping[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    real_compare = hmac.compare_digest

    def counting_compare(left: bytes, right: bytes) -> bool:
        calls.append(1)
        return real_compare(left, right)

    monkeypatch.setattr(hmac, "compare_digest", counting_compare)
    authenticate_api_key(fake_keys["administrator"], api_key_configuration)
    assert len(calls) == sum(len(p.key_digests) for p in api_key_configuration.principals)
