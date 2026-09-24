"""Do not destroy the native signing identity when Linux keyring sessions differ."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_command_control_authority import (
    AUTHORITY_FILE_NAME,
    AUTHORITY_MAX_BYTES,
    AUTHORITY_SCHEMA,
    encode_authority,
)
from codex_plugin_scanner.guard.native_command_control_authority_io import write_private_state
from codex_plugin_scanner.guard.native_policy_snapshot_codec import derive_native_policy_verifier_key
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NATIVE_POLICY_VERIFIER_KEY_NAME
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_policy_integrity_backend import MirroredPolicyIntegritySecretStore
from tests.test_guard_extension_control_authority import MemorySecretStore

PRIMARY = base64.urlsafe_b64encode(b"p" * 32).decode("ascii")
FALLBACK = base64.urlsafe_b64encode(b"f" * 32).decode("ascii")


def _setup(home: Path, *, signer: bytes = b"f" * 32) -> tuple[GuardStore, MirroredPolicyIntegritySecretStore]:
    store = GuardStore(home, prime_policy_integrity=False)
    backend = MirroredPolicyIntegritySecretStore(MemorySecretStore(), MemorySecretStore())
    store._policy_integrity_secret_store = backend
    backend.primary.set_secret(store._policy_integrity_key_ref, PRIMARY)
    backend.fallback.set_secret(store._policy_integrity_key_ref, FALLBACK)
    marker = {
        "schema": AUTHORITY_SCHEMA,
        "epoch": 2,
        "mutation_revision": 11,
        "authority_key_id": "0" * 64,
        "phase": "closed",
        "effective_digest": None,
        "recovery": None,
    }
    write_private_state(
        home,
        AUTHORITY_FILE_NAME,
        encode_authority(marker, derive_native_policy_verifier_key(signer)),
        AUTHORITY_MAX_BYTES,
    )
    return store, backend


def _assert_copies_preserved(store: GuardStore, backend: MirroredPolicyIntegritySecretStore) -> None:
    assert backend.primary.get_secret(store._policy_integrity_key_ref) == PRIMARY
    assert backend.fallback.get_secret(store._policy_integrity_key_ref) == FALLBACK


def test_authenticated_native_key_wins_without_replacing_either_backend(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path)
    write_private_state(tmp_path, NATIVE_POLICY_VERIFIER_KEY_NAME, derive_native_policy_verifier_key(b"f" * 32), 32)
    assert backend.get_policy_key(store._policy_integrity_key_ref, store=store) == FALLBACK
    _assert_copies_preserved(store, backend)


def test_authenticated_primary_repairs_the_stale_local_copy(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path, signer=b"p" * 32)
    assert backend.get_policy_key(store._policy_integrity_key_ref, store=store) == PRIMARY
    assert backend.fallback.get_secret(store._policy_integrity_key_ref) == PRIMARY


def test_unverifiable_marker_preserves_both_copies_for_explicit_recovery(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path, signer=b"x" * 32)
    assert backend.get_policy_key(store._policy_integrity_key_ref, store=store) == PRIMARY
    _assert_copies_preserved(store, backend)


@pytest.mark.parametrize("conflict", ["verifier", "floor", "malformed-marker"])
def test_partial_native_evidence_cannot_select_or_overwrite_a_key(tmp_path: Path, conflict: str) -> None:
    store, backend = _setup(tmp_path)
    if conflict == "verifier":
        write_private_state(tmp_path, NATIVE_POLICY_VERIFIER_KEY_NAME, derive_native_policy_verifier_key(b"p" * 32), 32)
    elif conflict == "floor":
        write_private_state(tmp_path, "policy-snapshot-v3.json", b"{}", 280 * 1024)
    else:
        write_private_state(tmp_path, AUTHORITY_FILE_NAME, b"{}", AUTHORITY_MAX_BYTES)
    assert backend.get_policy_key(store._policy_integrity_key_ref, store=store) == PRIMARY
    _assert_copies_preserved(store, backend)


@pytest.mark.parametrize("value", ["!", "not-a-key", "\u2603", base64.urlsafe_b64encode(b"short").decode("ascii")])
def test_malformed_primary_does_not_replace_the_authenticated_local_key(tmp_path: Path, value: str) -> None:
    store, backend = _setup(tmp_path)
    backend.primary.set_secret(store._policy_integrity_key_ref, value)
    assert backend.get_policy_key(store._policy_integrity_key_ref, store=store) == FALLBACK
    assert backend.fallback.get_secret(store._policy_integrity_key_ref) == FALLBACK
    assert backend.primary.get_secret(store._policy_integrity_key_ref) == value


def test_missing_marker_does_not_let_a_returning_keyring_destroy_the_local_copy(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path)
    (tmp_path / "native-runtime" / AUTHORITY_FILE_NAME).unlink()
    write_private_state(tmp_path, NATIVE_POLICY_VERIFIER_KEY_NAME, derive_native_policy_verifier_key(b"f" * 32), 32)
    assert backend.get_policy_key(store._policy_integrity_key_ref, store=store) == PRIMARY
    _assert_copies_preserved(store, backend)


def test_primary_unavailable_keeps_local_key_readable(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path)
    assert isinstance(backend.primary, MemorySecretStore)
    backend.primary.available = False
    assert backend.get_policy_key(store._policy_integrity_key_ref, store=store) == FALLBACK
    assert backend.fallback.get_secret(store._policy_integrity_key_ref) == FALLBACK


def test_first_publication_still_mirrors_primary(tmp_path: Path) -> None:
    store, backend = _setup(tmp_path)
    (tmp_path / "native-runtime" / AUTHORITY_FILE_NAME).unlink()
    assert backend.get_policy_key(store._policy_integrity_key_ref, store=store) == PRIMARY
    assert backend.fallback.get_secret(store._policy_integrity_key_ref) == PRIMARY
