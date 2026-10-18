"""
Adversarial Empirical Challenge Suite for Host Containment Engine (Requirement R2 / Milestone 1).
==================================================================================================

Empirically tests and stress-tests engine/host_containment.py:
1. Double-close, close before start, and rapid repeated close calls across all backends.
2. Concurrent multi-threaded stop() invocations (race conditions and handle use-after-free).
3. Exception propagation and guaranteed resource restoration inside context manager.
4. In-flight transaction abort during context manager exceptions and stop().
5. Exhaustive handle null/pointer guards across all WFP methods.
6. Handle cleanup even when FwpmEngineClose0 encounters unexpected exceptions.
7. Netlink binary framing fuzzer: 4-byte alignment, padding verification, length attribute overflow.
8. Adversarial / malformed inputs to apply_defensive_rule.
9. Subprocess silencing overrides and large stream handling.
10. Unprivileged permission fallback resilience.
"""

import concurrent.futures
import ctypes
from ctypes import wintypes
import os
import random
import socket
import struct
import subprocess
import sys
import threading
from unittest.mock import MagicMock, patch

import pytest

from engine.host_containment import (
    CREATE_NO_WINDOW,
    ERROR_SUCCESS,
    FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SESSION0,
    BaseContainmentBackend,
    HostContainmentManager,
    LinuxNetlinkContainmentBackend,
    MockContainmentBackend,
    WindowsWFPContainmentBackend,
    get_silent_subprocess_kwargs,
    silent_subprocess_popen,
    silent_subprocess_run,
)


# =============================================================================
# 1. Double-Close & Close Before Start Across All Backends
# =============================================================================

def test_adv_close_before_start_all_backends():
    """Empirically verifies calling stop() or close() on unstarted backends is safe."""
    # 1. HostContainmentManager
    mgr = HostContainmentManager(backend_override="mock")
    assert not mgr.is_active
    assert mgr.stop() is True
    mgr.close()
    assert not mgr.is_active

    # 2. WindowsWFPContainmentBackend
    wfp = WindowsWFPContainmentBackend()
    assert not wfp.is_active
    assert wfp._engine_handle is None
    assert wfp.stop() is True
    wfp.close()
    assert not wfp.is_active

    # 3. LinuxNetlinkContainmentBackend
    netlink = LinuxNetlinkContainmentBackend()
    assert not netlink.is_active
    assert netlink._sock is None
    assert netlink.stop() is True
    netlink.close()
    assert not netlink.is_active

    # 4. MockContainmentBackend
    mock = MockContainmentBackend()
    assert not mock.is_active
    assert mock.stop() is True
    mock.close()
    assert not mock.is_active


def test_adv_double_close_and_50x_repeated_close():
    """Empirically verifies calling stop() and close() 50 times in succession does not fail."""
    mgr = HostContainmentManager(backend_override="mock")
    mgr.start()
    assert mgr.is_active
    mgr.add_containment_rule("192.0.2.10", 80)

    # First stop
    assert mgr.stop() is True
    assert not mgr.is_active
    assert len(mgr.get_active_rules()) == 0

    # 50 repeated stop/close calls
    for i in range(50):
        if i % 2 == 0:
            assert mgr.stop() is True
        else:
            mgr.close()
        assert not mgr.is_active
        assert len(mgr.get_active_rules()) == 0


# =============================================================================
# 2. Concurrent Multi-Threaded stop() Invocations (Race Conditions)
# =============================================================================

def test_adv_concurrent_wfp_stop_single_close_guarantee():
    """
    Stress-tests WindowsWFPContainmentBackend.stop() under 50 concurrent threads.
    Verifies that FwpmEngineClose0 is called EXACTLY ONCE and no use-after-free occurs.
    """
    backend = WindowsWFPContainmentBackend()
    mock_dll = MagicMock()
    mock_dll.FwpmEngineOpen0.return_value = ERROR_SUCCESS
    mock_dll.FwpmEngineClose0.return_value = ERROR_SUCCESS

    def fake_open(s_name, authn, auth_id, sess_ptr, handle_ptr):
        ctypes.cast(handle_ptr, ctypes.POINTER(wintypes.HANDLE)).contents.value = 0xDEADBEEF
        return ERROR_SUCCESS

    mock_dll.FwpmEngineOpen0.side_effect = fake_open

    with patch.object(backend, "_get_dll", return_value=mock_dll):
        backend.start()
        assert backend.is_active
        assert backend._engine_handle is not None

        # Concurrently fire stop() from 50 threads
        exceptions = []
        barrier = threading.Barrier(50)

        def worker():
            try:
                barrier.wait(timeout=5)
                backend.stop()
            except Exception as e:
                exceptions.append(e)

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(exceptions) == 0, f"Concurrent stop raised exceptions: {exceptions}"
        assert not backend.is_active
        assert backend._engine_handle is None
        # Invariant: FwpmEngineClose0 must be called exactly once
        assert mock_dll.FwpmEngineClose0.call_count == 1


def test_adv_concurrent_manager_stop():
    """Stress-tests HostContainmentManager under 50 concurrent threads calling stop()."""
    mgr = HostContainmentManager(backend_override="mock")
    mgr.start()
    mgr.add_containment_rule("198.51.100.1", 443)

    barrier = threading.Barrier(50)
    exceptions = []

    def worker():
        try:
            barrier.wait(timeout=5)
            mgr.stop()
        except Exception as e:
            exceptions.append(e)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert len(exceptions) == 0
    assert not mgr.is_active
    assert len(mgr.get_active_rules()) == 0


# =============================================================================
# 3. Context Manager Exception Safety & Transaction Abort
# =============================================================================

def test_adv_context_manager_exception_propagation_and_cleanup():
    """Empirically verifies that exceptions inside with HostContainmentManager() propagate and clean up."""
    mgr = HostContainmentManager(backend_override="mock")

    class ContainmentTestException(Exception):
        pass

    with pytest.raises(ContainmentTestException, match="adversarial simulation"):
        with mgr:
            assert mgr.is_active
            mgr.add_containment_rule("10.0.0.99", 8080)
            assert len(mgr.get_active_rules()) == 1
            raise ContainmentTestException("adversarial simulation")

    # After exception: must be completely inactive and state cleared
    assert not mgr.is_active
    assert len(mgr.get_active_rules()) == 0


def test_adv_wfp_in_flight_transaction_aborted_on_stop():
    """
    Verifies that if stop() is called while an atomic transaction is active,
    FwpmTransactionAbort0 is called before FwpmEngineClose0.
    """
    backend = WindowsWFPContainmentBackend()
    mock_dll = MagicMock()
    mock_dll.FwpmEngineOpen0.return_value = ERROR_SUCCESS
    mock_dll.FwpmEngineClose0.return_value = ERROR_SUCCESS
    mock_dll.FwpmTransactionBegin0.return_value = ERROR_SUCCESS
    mock_dll.FwpmTransactionAbort0.return_value = ERROR_SUCCESS

    call_order = []
    mock_dll.FwpmTransactionAbort0.side_effect = lambda h: call_order.append("ABORT") or ERROR_SUCCESS
    mock_dll.FwpmEngineClose0.side_effect = lambda h: call_order.append("CLOSE") or ERROR_SUCCESS

    def fake_open(s_name, authn, auth_id, sess_ptr, handle_ptr):
        ctypes.cast(handle_ptr, ctypes.POINTER(wintypes.HANDLE)).contents.value = 0x12345678
        return ERROR_SUCCESS

    mock_dll.FwpmEngineOpen0.side_effect = fake_open

    with patch.object(backend, "_get_dll", return_value=mock_dll):
        backend.start()
        backend.transaction_begin()
        assert backend._in_transaction is True

        # Calling stop() while transaction is active
        backend.stop()

        assert backend._in_transaction is False
        assert backend._engine_handle is None
        assert not backend.is_active
        # Abort MUST happen before Close
        assert call_order == ["ABORT", "CLOSE"]


# =============================================================================
# 4. Exhaustive WFP Handle Null Dereference Guards
# =============================================================================

@pytest.mark.parametrize("bad_handle", [
    None,
    wintypes.HANDLE(None),
    wintypes.HANDLE(0),
])
def test_adv_wfp_handle_null_guards_exhaustive(bad_handle):
    """
    Verifies that all operations fail closed with RuntimeError if handle is None, 0, or wintypes.HANDLE(0).
    """
    backend = WindowsWFPContainmentBackend()
    backend._engine_handle = bad_handle

    with pytest.raises(RuntimeError, match="handle is null or closed"):
        backend.transaction_begin()

    with pytest.raises(RuntimeError, match="handle is null or closed"):
        backend.transaction_commit()

    with pytest.raises(RuntimeError, match="handle is null or closed"):
        backend.transaction_abort()

    with pytest.raises(RuntimeError, match="handle is null or closed"):
        backend.add_rule("192.0.2.1", 80)

    with pytest.raises(RuntimeError, match="handle is null or closed"):
        backend.remove_rule("WFP-RULE-0001-80")


def test_adv_wfp_start_null_handle_returned_fails_closed():
    """Verifies that if FwpmEngineOpen0 returns ERROR_SUCCESS but handle is null (0), start() fails closed."""
    backend = WindowsWFPContainmentBackend()
    mock_dll = MagicMock()
    # Return success, but leave handle as 0
    mock_dll.FwpmEngineOpen0.return_value = ERROR_SUCCESS

    def fake_open_null(s_name, authn, auth_id, sess_ptr, handle_ptr):
        ctypes.cast(handle_ptr, ctypes.POINTER(wintypes.HANDLE)).contents.value = 0
        return ERROR_SUCCESS

    mock_dll.FwpmEngineOpen0.side_effect = fake_open_null

    with patch.object(backend, "_get_dll", return_value=mock_dll):
        with pytest.raises(RuntimeError, match="returned a null handle"):
            backend.start()

        assert backend._engine_handle is None
        assert not backend.is_active


def test_adv_wfp_handle_nulled_even_if_close_raises():
    """
    Verifies that if FwpmEngineClose0 throws an exception or OS error,
    _engine_handle is STILL cleared to None, preventing use-after-free or dangling handles.
    """
    backend = WindowsWFPContainmentBackend()
    mock_dll = MagicMock()
    mock_dll.FwpmEngineOpen0.return_value = ERROR_SUCCESS
    mock_dll.FwpmEngineClose0.side_effect = OSError("Simulated Windows RPC error")

    def fake_open(s_name, authn, auth_id, sess_ptr, handle_ptr):
        ctypes.cast(handle_ptr, ctypes.POINTER(wintypes.HANDLE)).contents.value = 0xFEEDFACE
        return ERROR_SUCCESS

    mock_dll.FwpmEngineOpen0.side_effect = fake_open

    with patch.object(backend, "_get_dll", return_value=mock_dll):
        backend.start()
        assert backend.is_active
        assert backend._engine_handle is not None

        # Calling stop() should catch the error non-fatally, but MUST null out handle
        assert backend.stop() is True
        assert backend._engine_handle is None
        assert not backend.is_active

        # Subsequent stop does not raise
        assert backend.stop() is True


# =============================================================================
# 5. Linux Netlink Binary Framing Fuzzer & Stress Test
# =============================================================================

def test_adv_netlink_nlattr_alignment_fuzzer():
    """
    Empirically fuzzes pack_nlattr with 100 varying payload lengths (0 to 4096 bytes).
    Strictly verifies:
    1. Total length is ALWAYS a multiple of 4 (Linux Netlink 4-byte alignment rule).
    2. Header attribute length field is exactly 4 + payload_len.
    3. Payload is preserved verbatim.
    4. Any padding bytes are strictly null bytes (0x00).
    """
    backend = LinuxNetlinkContainmentBackend()

    # Deterministic seed for reproducibility
    rng = random.Random(0x42)
    test_lengths = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 63, 64, 127, 128, 255, 256, 1023, 1024]
    # Add random lengths
    test_lengths.extend(rng.randint(0, 2048) for _ in range(80))

    for length in test_lengths:
        payload = os.urandom(length)
        attr_type = rng.randint(1, 65535)

        packed = backend.pack_nlattr(attr_type, payload)

        # 1. 4-byte alignment
        assert len(packed) % 4 == 0, f"Netlink attribute not 4-byte aligned for payload len {length}"

        # 2. Minimum length is 4 bytes
        assert len(packed) >= 4

        # 3. Header fields
        unpacked_len, unpacked_type = struct.unpack("=HH", packed[:4])
        expected_nla_len = 4 + length
        assert unpacked_len == expected_nla_len, f"nla_len mismatch for payload len {length}: {unpacked_len} != {expected_nla_len}"
        assert unpacked_type == attr_type

        # 4. Payload integrity
        assert packed[4:4 + length] == payload

        # 5. Padding bytes must be null
        padding = packed[4 + length:]
        expected_pad_len = ((expected_nla_len + 3) & ~3) - expected_nla_len
        assert len(padding) == expected_pad_len
        assert padding == b"\x00" * expected_pad_len


def test_adv_netlink_nlattr_overflow_protection():
    """Verifies that an attribute payload exceeding 65531 bytes raises struct.error (16-bit length overflow)."""
    backend = LinuxNetlinkContainmentBackend()
    # 65532 + 4 = 65536 > 65535 (uint16 max)
    huge_payload = b"X" * 65532
    with pytest.raises(struct.error):
        backend.pack_nlattr(1, huge_payload)


def test_adv_netlink_batch_monotonic_sequence():
    """Verifies that batch begin/end messages increment sequence numbers monotonically."""
    backend = LinuxNetlinkContainmentBackend()
    initial_seq = backend._seq

    b1 = backend.build_batch_begin()
    seq1 = struct.unpack("=IHHII", b1[:16])[3]
    assert seq1 == initial_seq + 1

    b2 = backend.build_batch_end()
    seq2 = struct.unpack("=IHHII", b2[:16])[3]
    assert seq2 == seq1 + 1


# =============================================================================
# 6. Malformed & Adversarial Inputs to apply_defensive_rule
# =============================================================================

def test_adv_apply_defensive_rule_malformed_inputs():
    """Verifies apply_defensive_rule gracefully handles non-standard, null, or malformed inputs."""
    mgr = HostContainmentManager(backend_override="mock")
    mgr.start()

    # None input
    assert mgr.apply_defensive_rule(None) is True

    # Empty dict
    assert mgr.apply_defensive_rule({}) is True

    # Dict without target IP/port
    assert mgr.apply_defensive_rule({"action": "ALERT", "threat": "None"}) is True

    # Dict with non-integer port string
    assert mgr.apply_defensive_rule({"target_ip": "1.2.3.4", "target_port": "not_a_number"}) is False

    # Dict with valid string IP and port
    assert mgr.apply_defensive_rule({"target_ip": "198.51.100.5", "target_port": "8080"}) is True
    rules = mgr.get_active_rules()
    assert any(r["remote_ip"] == "198.51.100.5" and r["port"] == 8080 for r in rules)

    # Object with invalid IP causing backend exception
    class BadRule:
        target_ip = "invalid_ip_syntax"
        target_port = 80

    with patch.object(mgr, "add_containment_rule", side_effect=ValueError("Invalid IP")):
        # Should log warning and return False, not crash
        assert mgr.apply_defensive_rule(BadRule()) is False

    mgr.stop()


# =============================================================================
# 7. Subprocess Silencing Adversarial Edge Cases
# =============================================================================

def test_adv_subprocess_silencing_user_override_preservation():
    """Verifies that explicit user overrides in get_silent_subprocess_kwargs are strictly preserved."""
    # Custom stdin override (e.g. PIPE instead of DEVNULL)
    kw1 = get_silent_subprocess_kwargs(stdin=subprocess.PIPE)
    assert kw1["stdin"] == subprocess.PIPE

    # Custom creationflags override
    kw2 = get_silent_subprocess_kwargs(creationflags=0x00000000)
    assert kw2["creationflags"] == 0x00000000


def test_adv_silent_subprocess_run_large_output_and_stderr():
    """Verifies silent_subprocess_run handles commands writing to stderr and large output cleanly."""
    cmd = [
        sys.executable,
        "-c",
        "import sys; sys.stdout.write('O' * 10000); sys.stderr.write('E' * 5000); sys.exit(0)",
    ]
    res = silent_subprocess_run(cmd, capture_output=True, text=True, encoding="utf-8")
    assert res.returncode == 0
    assert len(res.stdout) == 10000
    assert len(res.stderr) == 5000


# =============================================================================
# 8. Unprivileged Fallback Resilience
# =============================================================================

def test_adv_manager_fallback_to_mock_when_wfp_permission_denied():
    """
    Verifies that if WindowsWFPContainmentBackend raises PermissionError,
    HostContainmentManager dynamically swaps to MockContainmentBackend without error.
    """
    mgr = HostContainmentManager(fallback_to_mock=True, backend_override="wfp")
    assert isinstance(mgr.backend, WindowsWFPContainmentBackend)

    with patch.object(WindowsWFPContainmentBackend, "start", side_effect=PermissionError("Access Denied: Non-Admin")):
        assert mgr.start() is True
        assert isinstance(mgr.backend, MockContainmentBackend)
        assert mgr.is_active

        # Verify operations work on the fallback
        assert mgr.add_containment_rule("203.0.113.1", 443) is True
        assert len(mgr.get_active_rules()) == 1

        assert mgr.stop() is True
        assert not mgr.is_active
