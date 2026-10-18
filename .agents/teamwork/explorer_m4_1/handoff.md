# Handoff Report: Target Authorization & SSRF Validation

**Agent**: Explorer M4-1 (Target Auth & SSRF Validation)  
**Milestone**: M4 (Security Boundaries & Concurrency Locks)  
**Date**: 2026-10-18T20:56:00Z  
**Type**: Hard Handoff (Investigation Complete)  
**Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\explorer_m4_1`  

---

## 1. Observation

1. **Auto-Whitelisting Bypass in `rfc_hunt_swarm.py:2268-2276`**:
   `rfc_hunt_swarm.py` lines 2268 to 2276 state verbatim:
   ```python
   2268:     # Authorize and validate each target host specified on the CLI
   2269:     from mcp_server import TargetAuthorizationGate
   2270:     for t_host, t_port, t_tls in target_list:
   2271:         TargetAuthorizationGate.authorize_target(t_host)
   2272:         is_valid_target, target_reason = TargetAuthorizationGate.validate_target(t_host)
   2273:         if not is_valid_target:
   2274:             print(f"[!] Target validation error for {t_host}: {target_reason}")
   2275:             sys.exit(1)
   ```
   In `mcp_server.py:44-50`, `authorize_target(cls, host: str)` executes `cls.ALLOWED_TARGETS.add(cleaned)`.
   Because `cls.ALLOWED_TARGETS` is mutated before line 2272 calls `validate_target(t_host)`, `validate_target` always returns `True` for any address other than `0.0.0.0` or `::`.

2. **Raw Socket Probers Lack Authorization and SSRF Checks**:
   - `deterministic_harness.py:48`: `raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)`. No import or call to `TargetAuthorizationGate` or `SafeNetworkValidator`.
   - `weaponizer.py:38`: `raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)`. Class has no authorization checks. When invoked via `main.py:192` (`cmd_weaponize`), no supervisor token or gate check is executed.
   - `engine/active_flaw_prober.py:57`: `raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)`. Dispatches canonical attack vectors without authorization checks.
   - `engine/differential_oracle.py:55`: `sock = socket.create_connection((target.host, target.port), timeout=target.timeout)`. No target validation; accepts arbitrary `TargetEndpoint`.
   - `protocol_ruler.py:92-93`: Only naive string check `if host in ("0.0.0.0", "::"): raise ValueError(...)`. Line 109 connects directly to `(self.host, self.port)`. Accepts `10.0.0.1`, `169.254.169.254`, etc.

3. **Absence of `engine/safe_network_validator.py`**:
   Attempting to inspect `D:\harfile\rfchunt\engine\safe_network_validator.py` returned file not found. A search across the repository for `ipaddress` confirmed that `ipaddress` is currently only imported inside RFC text documents (`rfcs/rfc8955.txt`, `rfcs/rfc8956.txt`), with zero imports in project Python files.

4. **Python `ipaddress` CGNAT Verification**:
   Executing `py -3.12 -c "import ipaddress; print(ipaddress.ip_address('100.64.0.1').is_private)"` outputs `False`. Standard `ip.is_private` does not block RFC 6598 CGNAT (`100.64.0.0/10`).

5. **Test Deficiencies in `tests/test_authorization_and_safety.py`**:
   The test suite contains 8 tests (`test_target_rejects_inaddr_any`, `test_target_rejects_wildcard_bypass`, `test_target_enforces_whitelist`, `test_payload_length_enforcement`, `test_sliding_window_rate_limiter`, `test_supervisor_token_enforcement`, `test_mcp_error_sanitization`, `test_database_defensive_intelligence_population`). Zero tests exist for RFC1918, CGNAT, link-local, cloud metadata, IPv6 ULA, IPv4-mapped IPv6, DNS rebinding, or prober-level gate enforcement.

---

## 2. Logic Chain

1. **Step 1 (Bypass Proof)**: Observation 1 demonstrates that calling `authorize_target(t_host)` on line 2271 mutates global process state in `cls.ALLOWED_TARGETS`. Since line 2272 validates membership in `cls.ALLOWED_TARGETS`, any target host supplied by a user or automated agent via `--host` or `--targets` is guaranteed to be accepted as authorized, completely bypassing the whitelist.
2. **Step 2 (Ungated Network Pivoting)**: Observation 2 proves that none of the five probers (`DeterministicHarness`, `RQPWeaponizer`, `ActiveFlawProber`, `MultiImplementationDifferentialOracle`, `ProtocolRuler`) validate target authorization or SSRF safety in their connection methods. Combining Step 1 and Step 2 means an external or unprivileged caller can force probers to probe arbitrary internal addresses.
3. **Step 3 (SSRF Gap)**: Observation 3 shows `engine/safe_network_validator.py` does not exist, leaving the codebase without any mathematical network validation layer.
4. **Step 4 (CGNAT Vulnerability)**: Observation 4 demonstrates that naive checks relying solely on `ip.is_private` will fail to block `100.64.0.0/10`, allowing probes into cloud provider internal network overlays and transit gateways.
5. **Step 5 (Regression Vulnerability)**: Observation 5 establishes that the current test suite does not guard against SSRF regressions, enabling unauthorized targets and internal IP probes to pass CI without detection.

---

## 3. Caveats

- **Lab Server Local Testing**: `test_lab_server.py` runs on `127.0.0.1`. When `allow_private=True` is explicitly passed (e.g., in unit tests or local test lab mode), loopback must be allowed, but Cloud Metadata (`169.254.169.254`, `fe80::/10`) and Unspecified (`0.0.0.0`, `::`) must remain strictly blocked.
- **DNS Resolution Testing in Offline CI**: Tests for DNS resolution and rebinding must either mock `socket.getaddrinfo` or use guaranteed local aliases (`localhost`, `.localhost`) to prevent reliance on external network connectivity during offline builds (`py -3.12 -u main.py build`).

---

## 4. Conclusion

The codebase requires four concrete, coordinated remediations for Milestone 4:
1. **Implement `engine/safe_network_validator.py`**: Providing `is_safe_target_ip(ip_str: str) -> bool` and `validate_target_host(target: str, allow_private: bool = False) -> Tuple[bool, str]`, with mathematical CIDR checks blocking RFC1918, Loopback, Link-Local/Cloud Metadata (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), IPv6 ULA (`fc00::/7`), Unspecified (`0.0.0.0/8`, `::`), IPv4-mapped IPv6 (`::ffff:0:0/96`), and multi-record DNS resolution checks.
2. **Remove Auto-Whitelisting in `rfc_hunt_swarm.py:2271`**: Eliminate `TargetAuthorizationGate.authorize_target(t_host)` from CLI parsing. Validate targets against `validate_target_host` and `TargetAuthorizationGate.validate_target` in fail-closed mode.
3. **Gate All Probers**: Integrate `TargetAuthorizationGate.check_target` and `validate_target_host` into `DeterministicHarness`, `RQPWeaponizer`, `ActiveFlawProber`, `MultiImplementationDifferentialOracle`, and `ProtocolRuler`.
4. **Expand `tests/test_authorization_and_safety.py`**: Add comprehensive test coverage for all 8 IP range categories, cloud metadata immunity, DNS rebinding, and prober fail-closed gating.

Detailed code references and diff specifications are documented in `D:\harfile\rfchunt\.agents\teamwork\explorer_m4_1\report.md`.

---

## 5. Verification Method

To independently verify the observations:
1. **Verify Auto-Whitelisting Bug**:
   Inspect lines 2268-2276 in `rfc_hunt_swarm.py` via `view_file` or run:
   ```powershell
   py -3.12 -c "from mcp_server import TargetAuthorizationGate; TargetAuthorizationGate.authorize_target('169.254.169.254'); ok, reason = TargetAuthorizationGate.validate_target('169.254.169.254'); print('Allowed:', ok, reason)"
   ```
   Assert that this prints `Allowed: True Target '169.254.169.254' is authorized.`, confirming the bypass.
2. **Verify Missing Validator**:
   Run `Test-Path D:\harfile\rfchunt\engine\safe_network_validator.py` in powershell, confirming `False`.
3. **Verify CGNAT Behavior**:
   Run `py -3.12 -c "import ipaddress; assert not ipaddress.ip_address('100.64.0.1').is_private"` to confirm `is_private` evaluates to `False`.
4. **Run Existing Test Suite**:
   Run `py -3.12 -m pytest tests/test_authorization_and_safety.py -v` to observe existing 8 tests passing without any SSRF coverage.
