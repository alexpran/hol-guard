"""Issue #3089: enrollment errors and authenticated native-authority recovery."""

from __future__ import annotations

import argparse
import io
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import ApprovalGateInput, update_settings
from codex_plugin_scanner.guard.cli import extension_controls_commands as cli
from codex_plugin_scanner.guard.native_command_control_authority import (
    AUTHORITY_FILE_NAME,
    AUTHORITY_MAX_BYTES,
    AUTHORITY_SCHEMA,
    encode_authority,
)
from codex_plugin_scanner.guard.native_command_control_authority_io import write_private_state
from codex_plugin_scanner.guard.native_command_control_authority_store import _key, read_command_control_authority
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.store import GuardStore, SystemKeyringSecretStore

PASSWORD = "enrollment regression password"


@pytest.fixture
def stale_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(SystemKeyringSecretStore, "_backend_is_available", classmethod(lambda cls: False))
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )
    monkeypatch.setattr(cli, "prompt_for_approval_gate", lambda *_args, **_kwargs: ApprovalGateInput(password=PASSWORD))
    update_settings(tmp_path, {"enabled": True, "new_password": PASSWORD, "confirm_password": PASSWORD})
    store = GuardStore(tmp_path)
    _key(store)
    marker = {
        "schema": AUTHORITY_SCHEMA,
        "epoch": 1,
        "mutation_revision": 1,
        "authority_key_id": "0" * 64,
        "phase": "closed",
        "effective_digest": None,
        "recovery": None,
    }
    write_private_state(tmp_path, AUTHORITY_FILE_NAME, encode_authority(marker, b"s" * 32), AUTHORITY_MAX_BYTES)
    return tmp_path


def _run(home: Path, command: str) -> tuple[int, str]:
    output = io.StringIO()
    result = cli.run_extension_controls_command(
        argparse.Namespace(controls_command=command, actor="local-admin"), guard_home=home, output_stream=output
    )
    return result, output.getvalue()


def test_stale_native_marker_returns_actionable_error_without_changing_authority(
    stale_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = stale_home / "native-runtime" / AUTHORITY_FILE_NAME
    before = path.read_bytes()
    result, output = _run(stale_home, "enroll")
    assert result == 4
    assert output == ""
    error = capsys.readouterr().err
    assert "recover-authority" in error
    assert "Traceback" not in error
    assert path.read_bytes() == before
    store = GuardStore(stale_home)
    assert (
        store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY).health
        is AuthorityHealth.UNENROLLED
    )


def test_explicit_recovery_repairs_stale_marker_without_deleting_native_state(stale_home: Path) -> None:
    result, output = _run(stale_home, "recover-authority")
    assert result == 0
    assert '"health":"protected"' in output
    store = GuardStore(stale_home)
    assert read_command_control_authority(store, _key(store)) is not None
    assert (
        store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY).health
        is AuthorityHealth.PROTECTED
    )


def test_returning_linux_keyring_does_not_overwrite_the_live_daemon_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import base64

    from tests.test_guard_extension_control_authority import MemorySecretStore, _enroll, _store

    keyring_values: dict[str, str] = {}
    monkeypatch.setattr(SystemKeyringSecretStore, "_backend_is_available", classmethod(lambda cls: False))
    daemon = _store(tmp_path, MemorySecretStore(), enroll=False)
    verifier_key = _key(daemon)
    marker = {
        "schema": AUTHORITY_SCHEMA,
        "epoch": 1,
        "mutation_revision": 1,
        "authority_key_id": "0" * 64,
        "phase": "closed",
        "effective_digest": None,
        "recovery": None,
    }
    encoded = encode_authority(marker, verifier_key)
    write_private_state(tmp_path, AUTHORITY_FILE_NAME, encoded, AUTHORITY_MAX_BYTES)
    keyring_values[daemon._policy_integrity_key_ref] = base64.urlsafe_b64encode(b"o" * 32).decode("ascii")
    monkeypatch.setattr(SystemKeyringSecretStore, "_backend_is_available", classmethod(lambda cls: True))
    monkeypatch.setattr(SystemKeyringSecretStore, "get_secret", lambda _self, secret_id: keyring_values.get(secret_id))
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "set_secret",
        lambda _self, secret_id, value: keyring_values.__setitem__(secret_id, value),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )
    terminal = GuardStore(tmp_path, prime_policy_integrity=False)
    terminal._extension_control_authority_secret_store = daemon._extension_control_authority_secret_store
    assert _enroll(terminal).health is AuthorityHealth.PROTECTED
    assert _key(terminal) == verifier_key
    assert read_command_control_authority(daemon, verifier_key) is not None


def test_recovery_rejects_wrong_password_without_touching_native_state(
    stale_home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = stale_home / "native-runtime" / AUTHORITY_FILE_NAME
    before = path.read_bytes()
    monkeypatch.setattr(
        cli, "prompt_for_approval_gate", lambda *_args, **_kwargs: ApprovalGateInput(password="incorrect")
    )
    result, output = _run(stale_home, "recover-authority")
    assert result == 4
    assert output == ""
    assert "Traceback" not in capsys.readouterr().err
    assert path.read_bytes() == before


def test_recovery_refuses_a_forged_retained_floor_without_traceback(
    stale_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = stale_home / "native-runtime" / AUTHORITY_FILE_NAME
    before = path.read_bytes()
    write_private_state(stale_home, "policy-snapshot-v3.json", b"{}", 280 * 1024)
    result, output = _run(stale_home, "recover-authority")
    assert result == 4
    assert output == ""
    error = capsys.readouterr().err
    assert "restore access" in error
    assert "Do not delete" in error
    assert "Traceback" not in error
    assert path.read_bytes() == before
    assert (stale_home / "native-runtime" / "policy-snapshot-v3.json").read_bytes() == b"{}"


def test_recovery_preserves_an_authenticated_floor_and_advances_the_epoch(stale_home: Path) -> None:
    from codex_plugin_scanner.guard.native_command_control_binding import native_command_control_floor_mac
    from codex_plugin_scanner.guard.native_policy_snapshot_codec import _canonical_json_bytes_v3

    store = GuardStore(stale_home)
    verifier = _key(store)
    floor = {
        "revision": 3,
        "managed_revision": 0,
        "effective_digest": "e" * 64,
        "authority": {"epoch": 2, "mutation_revision": 9, "authority_key_id": "0" * 64, "recovery": None},
    }
    retained = {
        "schema": "guard-policy-snapshot-authority.v3",
        "generation_floor": 7,
        "policy_digest": "d" * 64,
        "snapshot": None,
        "command_control_floor": floor,
        "floor_mac": native_command_control_floor_mac(7, "d" * 64, floor, verifier),
    }
    encoded = _canonical_json_bytes_v3(retained)
    write_private_state(stale_home, "policy-snapshot-v3.json", encoded, 280 * 1024)
    result, output = _run(stale_home, "recover-authority")
    assert result == 0
    assert '"health":"protected"' in output
    assert (stale_home / "native-runtime" / "policy-snapshot-v3.json").read_bytes() == encoded
    marker = read_command_control_authority(store, verifier)
    assert marker is not None
    assert marker["epoch"] > 2
    assert marker["mutation_revision"] > 9
    assert marker["recovery"]["previous_epoch"] == 2


def test_reenrollment_points_to_recovery_before_requesting_factors(
    stale_home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _run(stale_home, "recover-authority")[0] == 0

    def unexpected_prompt(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Existing authority must not request another enrollment proof")

    monkeypatch.setattr(cli, "prompt_for_approval_gate", unexpected_prompt)
    result, output = _run(stale_home, "enroll")
    assert result == 4
    assert output == ""
    error = capsys.readouterr().err
    assert "recover-authority" in error
    assert str(stale_home) in error
    assert "Traceback" not in error
