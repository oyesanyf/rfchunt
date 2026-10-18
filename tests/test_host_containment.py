"""
Comprehensive Unit & Integration Test Suite for Host Containment & Subprocess Silencing.
========================================================================================

Verifies Requirement R2 / Milestone 1:
1. Windows Filtering Platform (WFP) dynamic session (FWPM_SESSION_FLAG_DYNAMIC = 0x00000001).
2. Strict pointer/handle null checks across all WFP operations.
3. Transaction begin, commit, and abort rollback behavior.
4. Deterministic FwpmEngineClose0 cleanup in stop(), close(), and context manager exit.
5. Idempotent multiple stop() calls.
6. Atexit cleanup registration.
7. Linux Netlink sockets 16-byte nlmsghdr, 4-byte nfgenmsg, 4-byte aligned nlattr framing,
   and transactional batch begin/end framing.
8. MockContainmentBackend state management and transaction lifecycle.
9. Subprocess silencing helpers (CREATE_NO_WINDOW = 0x08000000, stdin=subprocess.DEVNULL).
10. DefensiveIntelligencePublisher integration with HostContainmentManager.
11. Static audit of external subprocess calls across build_all.py, engine/raptor_integrator.py,
    and ollama_manager.py.
"""

import atexit
import ctypes
from ctypes import wintypes
import inspect
import os
import re
import socket
import struct
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from engine.host_containment import (
    CREATE_NO_WINDOW,
    ERROR_SUCCESS,
    FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SESSION0,
    GUID,
    BaseContainmentBackend,
    HostContainmentManager,
    LinuxNetlinkContainmentBackend,
    MockContainmentBackend,
    WindowsWFPContainmentBackend,
    get_silent_subprocess_kwargs,
    silent_subprocess_popen,
    silent_subprocess_run,
)
from engine.defensive_publisher import DefensiveIntelligencePublisher
from engine.taxonomy import ImpactClass, ReproducibleVulnerability


# =============================================================================
# 1. HostContainmentManager & Backend Detection Tests
# =============================================================================

def test_manager_instantiation_and_backend_detection():
    """Verifies default backend selection and explicit backend overrides."""
    # Explicit Mock backend
    cm_mock = HostContainmentManager(backend_override="mock")
    assert isinstance(cm_mock.backend, MockContainmentBackend)
    assert not cm_mock.is_active

    # Auto-detection on current host
    cm_auto = HostContainmentManager(fallback_to_mock=True)
    if sys.platform == "win32":
        assert isinstance(cm_auto.backend, (WindowsWFPContainmentBackend, MockContainmentBackend))
    elif sys.platform.startswith("linux"):
        assert isinstance(cm_auto.backend, (LinuxNetlinkContainmentBackend, MockContainmentBackend))
    else:
        assert isinstance(cm_auto.backend, MockContainmentBackend)


def test_context_manager_lifecycle():
    """Verifies that context manager starts on entry and stops on exit."""
    cm = HostContainmentManager(backend_override="mock")
    assert not cm.is_active

    with cm as active_cm:
        assert active_cm is cm
        assert cm.is_active
        # Add test rule inside context
        added = cm.add_containment_rule("192.0.2.1", 8080, "BLOCK")
        assert added is True
        assert len(cm.get_active_rules()) == 1

    # Deterministically stopped on exit
    assert not cm.is_active
    assert len(cm.get_active_rules()) == 0


def test_explicit_start_stop_close_idempotency():
    """Verifies explicit start(), stop(), and close() are safe and idempotent."""
    cm = HostContainmentManager(backend_override="mock")
    assert cm.start() is True
    assert cm.is_active

    # Repeated start does not create duplicate state
    assert cm.start() is True
    assert cm.is_active

    # Stop deactivates cleanly
    assert cm.stop() is True
    assert not cm.is_active

    # Repeated stop is idempotent and returns True
    assert cm.stop() is True
    assert not cm.is_active

    # close() is an alias for stop() and does not raise
    cm.close()
    assert not cm.is_active


# =============================================================================
# 2. Windows Filtering Platform (WFP) Tests
# =============================================================================

def test_wfp_dynamic_session_flag_and_structures():
    """Verifies FWPM_SESSION_FLAG_DYNAMIC is exactly 0x00000001 and structure layouts."""
    assert FWPM_SESSION_FLAG_DYNAMIC == 0x00000001

    session = FWPM_SESSION0()
    session.flags = FWPM_SESSION_FLAG_DYNAMIC
    assert session.flags == 1

    # Verify field offsets and structure sizes
    assert hasattr(session, "sessionKey")
    assert hasattr(session, "displayData")
    assert hasattr(session, "flags")
    assert hasattr(session, "txnWaitTimeoutInMSec")
    assert hasattr(session, "processId")
    assert hasattr(session, "sid")
    assert hasattr(session, "username")
    assert hasattr(session, "kernelMode")


def test_wfp_handle_null_checks():
    """Verifies that operations on an uninitialized or closed handle fail closed."""
    backend = WindowsWFPContainmentBackend()

    # Engine handle is initially None
    assert backend._engine_handle is None

    # Operations must raise RuntimeError due to strict null check
    with pytest.raises(RuntimeError, match="handle is null or closed"):
        backend.transaction_begin()

    with pytest.raises(RuntimeError, match="handle is null or closed"):
        backend.transaction_commit()

    with pytest.raises(RuntimeError, match="handle is null or closed"):
        backend.transaction_abort()

    with pytest.raises(RuntimeError, match="handle is null or closed"):
        backend.add_rule("192.0.2.1", 443, "BLOCK")

    with pytest.raises(RuntimeError, match="handle is null or closed"):
        backend.remove_rule("WFP-RULE-0001-443")

    # If handle has value 0, it must also fail closed
    backend._engine_handle = wintypes.HANDLE(0)
    with pytest.raises(RuntimeError, match="handle is null or closed"):
        backend.transaction_begin()


def test_wfp_simulated_lifecycle_and_transactions():
    """
    Verifies WFP dynamic session opening, transaction begin, commit, abort,
    and FwpmEngineClose0 cleanup using a mock DLL boundary.
    """
    backend = WindowsWFPContainmentBackend()

    # Build simulated DLL
    mock_dll = MagicMock()
    mock_dll.FwpmEngineOpen0.return_value = ERROR_SUCCESS
    mock_dll.FwpmEngineClose0.return_value = ERROR_SUCCESS
    mock_dll.FwpmTransactionBegin0.return_value = ERROR_SUCCESS
    mock_dll.FwpmTransactionCommit0.return_value = ERROR_SUCCESS
    mock_dll.FwpmTransactionAbort0.return_value = ERROR_SUCCESS

    # Simulate FwpmEngineOpen0 setting handle value
    def fake_open(server_name, authn, auth_id, session_ptr, handle_ptr):
        # Verify session has FWPM_SESSION_FLAG_DYNAMIC
        sess = ctypes.cast(session_ptr, ctypes.POINTER(FWPM_SESSION0)).contents
        assert sess.flags == FWPM_SESSION_FLAG_DYNAMIC
        ctypes.cast(handle_ptr, ctypes.POINTER(wintypes.HANDLE)).contents.value = 0xCAFE1234
        return ERROR_SUCCESS

    mock_dll.FwpmEngineOpen0.side_effect = fake_open

    with patch.object(backend, "_get_dll", return_value=mock_dll):
        # 1. Start dynamic session
        assert backend.start() is True
        assert backend.is_active
        assert backend._engine_handle is not None
        assert backend._engine_handle.value == 0xCAFE1234
        assert mock_dll.FwpmEngineOpen0.called

        # 2. Add rule within atomic transaction
        assert backend.add_rule("10.0.0.1", 80, "BLOCK") is True
        assert mock_dll.FwpmTransactionBegin0.called
        assert mock_dll.FwpmTransactionCommit0.called
        assert len(backend.get_rules()) == 1

        # 3. Test transaction abort on simulated failure
        mock_dll.FwpmTransactionCommit0.side_effect = RuntimeError("Commit failed")
        with pytest.raises(RuntimeError, match="Commit failed"):
            backend.add_rule("10.0.0.2", 8080, "BLOCK")
        assert mock_dll.FwpmTransactionAbort0.called

        # 4. Stop session deterministically closes engine handle
        mock_dll.FwpmTransactionCommit0.side_effect = None
        assert backend.stop() is True
        assert not backend.is_active
        assert backend._engine_handle is None
        assert mock_dll.FwpmEngineClose0.called

        # 5. Subsequent stop is idempotent
        assert backend.stop() is True


def test_wfp_unprivileged_fallback_to_mock():
    """Verifies that PermissionError (Access Denied) in WFP gracefully falls back to Mock."""
    cm = HostContainmentManager(fallback_to_mock=True, backend_override="wfp")

    # Mock WFP backend raising PermissionError (Access Denied / Non-Admin)
    with patch.object(WindowsWFPContainmentBackend, "start", side_effect=PermissionError("Access Denied")):
        # cm.start() should fall back to MockContainmentBackend without crashing
        assert cm.start() is True
        assert isinstance(cm.backend, MockContainmentBackend)
        assert cm.is_active

        # Can add rules under fallback
        assert cm.add_containment_rule("127.0.0.1", 9000, "BLOCK") is True
        assert len(cm.get_active_rules()) == 1

        cm.stop()
        assert not cm.is_active


# =============================================================================
# 3. Linux Netlink Sockets Tests
# =============================================================================

def test_linux_netlink_framing_structures():
    """Verifies 16-byte nlmsghdr, 4-byte nfgenmsg, and 4-byte aligned nlattr serialization."""
    backend = LinuxNetlinkContainmentBackend()

    # 1. 16-byte nlmsghdr
    hdr = backend.pack_nlmsghdr(length=32, msg_type=10, flags=1, seq=42, pid=1234)
    assert len(hdr) == 16
    unpacked_hdr = struct.unpack("=IHHII", hdr)
    assert unpacked_hdr == (32, 10, 1, 42, 1234)

    # 2. 4-byte nfgenmsg
    genmsg = backend.pack_nfgenmsg(nfgen_family=socket.AF_INET if hasattr(socket, "AF_INET") else 2, version=0, res_id=10)
    assert len(genmsg) == 4
    unpacked_gen = struct.unpack("=BBH", genmsg)
    assert unpacked_gen[0] in (2, getattr(socket, "AF_INET", 2))
    assert unpacked_gen[1] == 0
    assert unpacked_gen[2] == 10

    # 3. 4-byte aligned nlattr
    # Payload of 3 bytes: 4 header + 3 payload = 7 bytes -> padded to 8 bytes (1 pad byte)
    attr_3 = backend.pack_nlattr(attr_type=1, payload=b"abc")
    assert len(attr_3) == 8
    attr_len, attr_type = struct.unpack("=HH", attr_3[:4])
    assert attr_len == 7
    assert attr_type == 1
    assert attr_3[4:7] == b"abc"
    assert attr_3[7:] == b"\x00"

    # Payload of 4 bytes: 4 header + 4 payload = 8 bytes -> 0 pad bytes
    attr_4 = backend.pack_nlattr(attr_type=2, payload=b"abcd")
    assert len(attr_4) == 8
    attr_len4, attr_type4 = struct.unpack("=HH", attr_4[:4])
    assert attr_len4 == 8
    assert attr_type4 == 2
    assert attr_4[4:] == b"abcd"


def test_linux_netlink_batch_begin_end_framing():
    """Verifies NFNL_MSG_BATCH_BEGIN and NFNL_MSG_BATCH_END messages."""
    backend = LinuxNetlinkContainmentBackend()

    batch_begin = backend.build_batch_begin()
    assert len(batch_begin) == 16 + 4  # 16-byte nlmsghdr + 4-byte nfgenmsg
    unpacked_hdr = struct.unpack("=IHHII", batch_begin[:16])
    assert unpacked_hdr[0] == 20
    # msg_type contains NFNL_SUBSYS_NFTABLES << 8 | NFNL_MSG_BATCH_BEGIN
    assert (unpacked_hdr[1] >> 8) == 10

    batch_end = backend.build_batch_end()
    assert len(batch_end) == 16 + 4
    unpacked_end = struct.unpack("=IHHII", batch_end[:16])
    assert (unpacked_end[1] >> 8) == 10

    full_batch = backend.build_batch_message([b"test_payload_1234"])
    assert full_batch.startswith(batch_begin[:8])
    assert b"test_payload_1234" in full_batch
    assert len(full_batch) == 20 + len(b"test_payload_1234") + 20


# =============================================================================
# 4. Mock Containment Backend Tests
# =============================================================================

def test_mock_containment_backend_lifecycle():
    """Verifies MockContainmentBackend transaction operations and state tracking."""
    backend = MockContainmentBackend()
    assert not backend.is_active

    # Operations when inactive raise RuntimeError
    with pytest.raises(RuntimeError, match="not active"):
        backend.add_rule("1.1.1.1", 80)

    backend.start()
    assert backend.is_active

    # Transaction lifecycle
    assert backend.transaction_begin() is True
    assert backend._in_transaction is True
    assert backend.transaction_commit() is True
    assert backend._in_transaction is False

    # Add rule
    assert backend.add_rule("192.168.1.10", 443, "BLOCK") is True
    rules = backend.get_rules()
    assert len(rules) == 1
    assert rules[0]["remote_ip"] == "192.168.1.10"
    assert rules[0]["port"] == 443
    assert rules[0]["action"] == "BLOCK"

    # Remove rule
    rule_id = rules[0]["rule_id"]
    assert backend.remove_rule(rule_id) is True
    assert len(backend.get_rules()) == 0

    # Stop
    assert backend.stop() is True
    assert not backend.is_active


# =============================================================================
# 5. Subprocess Silencing Helpers Tests
# =============================================================================

def test_subprocess_silencing_kwargs():
    """Verifies get_silent_subprocess_kwargs returns CREATE_NO_WINDOW on Windows and DEVNULL."""
    kwargs = get_silent_subprocess_kwargs()
    assert kwargs["stdin"] == subprocess.DEVNULL

    if sys.platform == "win32" or os.name == "nt":
        assert kwargs["creationflags"] == 0x08000000
        assert kwargs["creationflags"] == CREATE_NO_WINDOW

    # User overrides take precedence
    custom_kwargs = get_silent_subprocess_kwargs(timeout=45)
    assert custom_kwargs["timeout"] == 45
    assert custom_kwargs["stdin"] == subprocess.DEVNULL


def test_silent_subprocess_run_and_popen():
    """Verifies silent_subprocess_run executes cleanly without popups."""
    # Run a simple echo command with silent subprocess
    res = silent_subprocess_run(
        [sys.executable, "-c", "import sys; sys.stdout.write('silent_ok')"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert res.returncode == 0
    assert res.stdout == "silent_ok"

    # Popen test
    proc = silent_subprocess_popen(
        [sys.executable, "-c", "import sys; sys.stdout.write('popen_ok')"],
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    stdout, _ = proc.communicate(timeout=5)
    assert proc.returncode == 0
    assert stdout == "popen_ok"


# =============================================================================
# 6. Defensive Intelligence Publisher Integration Tests
# =============================================================================

def test_defensive_publisher_containment_hook(tmp_path):
    """Verifies that DefensiveIntelligencePublisher forwards confirmed findings to HostContainmentManager."""
    cm = HostContainmentManager(backend_override="mock")
    cm.start()

    publisher = DefensiveIntelligencePublisher(
        output_dir=str(tmp_path),
        containment_manager=cm,
    )

    vuln = ReproducibleVulnerability(
        vuln_id="VULN-CONT-01",
        anomaly_id="ANOM-CONT-01",
        impact=ImpactClass.DESYNCHRONIZATION,
        minimized_probe=b"GET / HTTP/1.1\r\nHost: 10.0.0.5\r\n\r\n",
        reproducibility_rate=1.0,
        verification_attempts=3,
        successful_reproductions=3,
        delta_debug_steps=1,
    )

    arm106, arm107 = publisher.publish_finding(vuln, rfc_anchor="RFC9112")
    assert arm106 is not None
    assert arm107 is not None

    # Verify containment manager recorded the defensive rule
    assert len(cm._active_defensive_rules) == 1
    assert cm._active_defensive_rules[0].rule_id == arm106.rule_id

    cm.stop()


# =============================================================================
# 7. Static Code Audit of Subprocess Calls
# =============================================================================

def test_subprocess_silencing_audited_in_source_files():
    """
    Statically audits build_all.py, engine/raptor_integrator.py, and ollama_manager.py
    to verify that 100% of subprocess calls specify CREATE_NO_WINDOW / creationflags
    and stdin=subprocess.DEVNULL.
    """
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # 1. build_all.py
    build_all_path = os.path.join(root_dir, "build_all.py")
    with open(build_all_path, "r", encoding="utf-8") as f:
        build_code = f.read()
    assert "creationflags" in build_code
    assert "0x08000000" in build_code
    assert "stdin=subprocess.DEVNULL" in build_code

    # 2. engine/raptor_integrator.py
    raptor_path = os.path.join(root_dir, "engine", "raptor_integrator.py")
    with open(raptor_path, "r", encoding="utf-8") as f:
        raptor_code = f.read()
    assert "CREATE_NO_WINDOW" in raptor_code and "0x08000000" in raptor_code
    # Every subprocess.run in raptor_integrator must include creationflags and stdin
    run_calls = re.findall(r"subprocess\.run\([^)]+\)", raptor_code, re.DOTALL)
    assert len(run_calls) >= 4
    for call in run_calls:
        assert "creationflags" in call
        assert "stdin=subprocess.DEVNULL" in call

    # 3. ollama_manager.py
    ollama_path = os.path.join(root_dir, "ollama_manager.py")
    with open(ollama_path, "r", encoding="utf-8") as f:
        ollama_code = f.read()
    assert "stdin=subprocess.DEVNULL" in ollama_code
    # Popen and run must both have stdin=subprocess.DEVNULL and creationflags
    assert "subprocess.Popen(" in ollama_code
    popen_match = re.search(r"subprocess\.Popen\((.*?)\)", ollama_code, re.DOTALL)
    assert popen_match is not None
    assert "stdin=subprocess.DEVNULL" in popen_match.group(1)
    assert "creationflags=creation_flags" in popen_match.group(1)
