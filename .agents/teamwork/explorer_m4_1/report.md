# Comprehensive Technical Investigation Report: Target Authorization & SSRF Validation

**Agent**: Explorer M4-1 (Target Auth & SSRF Validation)  
**Milestone**: M4 (Security Boundaries & Concurrency Locks)  
**Date**: 2026-10-18T20:55:00Z  
**Repository**: `D:\harfile\rfchunt`  
**Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\explorer_m4_1`  

---

## 1. Executive Summary

This investigation analyzed target authorization mechanics and mathematical Server-Side Request Forgery (SSRF) defenses across the HTTP Terminator / RFC Hunt Swarm codebase (`D:\harfile\rfchunt`). 

Three primary critical security vulnerabilities were uncovered:
1. **CLI Auto-Whitelisting Bypass (`rfc_hunt_swarm.py:2269-2276`)**: Whenever targets are supplied via `--host` or `--targets`, `rfc_hunt_swarm.py` immediately calls `TargetAuthorizationGate.authorize_target(t_host)` before calling `validate_target(t_host)`. Because `authorize_target` permanently appends the target to the global in-memory whitelist `cls.ALLOWED_TARGETS`, any target passed on the CLI—including private subnets (`10.0.0.1`), cloud metadata endpoints (`169.254.169.254`), or arbitrary third-party servers—is auto-authorized, rendering the authorization check completely non-functional.
2. **Ungated Raw Socket Probers**: Core network evaluation probers (`DeterministicHarness`, `RQPWeaponizer`, `ActiveFlawProber`, `MultiImplementationDifferentialOracle`, and `ProtocolRuler`) open raw TCP sockets directly (`socket.create_connection`) with zero target authorization checks and zero SSRF validation. `ProtocolRuler` possesses only a naive check for string literals `"0.0.0.0"` and `"::"`. If instantiated directly (e.g., via `main.py` CLI commands or background workers), any prober will connect to private or metadata addresses.
3. **Missing `engine/safe_network_validator.py` & Inadequate Test Coverage**: The required mathematical SSRF validation module (`engine/safe_network_validator.py`) does not exist in the codebase. Furthermore, `tests/test_authorization_and_safety.py` only validates 8 basic MCP/token tests, completely omitting all mathematical IP range tests (RFC1918, CGNAT, Link-Local, Cloud Metadata, IPv6 ULA, Unspecified, IPv4-mapped IPv6, and DNS rebinding).
4. **The Python `ipaddress` CGNAT Trap**: In Python's standard `ipaddress` module, `ipaddress.ip_address('100.64.0.1').is_private` evaluates to `False`. A naive check relying solely on `ip.is_private` fails to block Carrier-Grade NAT (`100.64.0.0/10`), which is frequently used for cloud VPC transit gateways, container overlay networks, and VPN mesh interfaces.

---

## 2. Detailed Vulnerability Analysis

### Vulnerability 1: CLI Auto-Whitelisting Bypass in `rfc_hunt_swarm.py`

#### Exact Location
`D:\harfile\rfchunt\rfc_hunt_swarm.py:2268-2276`:

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

#### Mechanism of the Flaw
In `mcp_server.py:44-51`:
```python
    @classmethod
    def authorize_target(cls, host: str) -> None:
        cleaned = host.strip().lower()
        if cleaned in ("0.0.0.0", "::"):
            raise ValueError("Cannot authorize 0.0.0.0 or :: (INADDR_ANY listening address). Specify a valid host or loopback.")
        if cleaned in ("*", "all"):
            raise ValueError("Wildcard authorization is disallowed. Specify explicit target hostnames or IPs.")
        cls.ALLOWED_TARGETS.add(cleaned)
```

And `validate_target(host)` in `mcp_server.py:66-71`:
```python
    @classmethod
    def validate_target(cls, host: str) -> Tuple[bool, str]:
        try:
            cls.check_target(host)
            return True, f"Target '{host}' is authorized."
        except (ValueError, PermissionError) as e:
            return False, str(e)
```
Where `check_target(host)` checks:
```python
        allowed = cls.get_allowed_targets()
        if cleaned not in allowed:
            raise PermissionError(...)
```

#### Impact
1. `TargetAuthorizationGate.authorize_target(t_host)` unconditionally inserts `t_host` into `cls.ALLOWED_TARGETS`.
2. Next line, `validate_target(t_host)` checks if `t_host` is in `cls.ALLOWED_TARGETS`. It is always present!
3. The validation check `if not is_valid_target:` can never be triggered for any non-listening address.
4. An operator or automated pipeline running `python rfc_hunt_swarm.py --host 169.254.169.254` or `python rfc_hunt_swarm.py --host 10.10.10.1` will auto-authorize the target, bypassing all whitelist and authorization boundaries.
5. In addition, because `cls.ALLOWED_TARGETS` is a shared class attribute, the target remains permanently authorized across all subsequent tasks or MCP queries executing within the same process.

---

### Vulnerability 2: Target Authorization Enforcement Across Raw Socket Probers

An audit of all probers and components that create raw network sockets was conducted.

#### 1. `deterministic_harness.py` (`DeterministicHarness`)
- **Socket Creation**: Line 48:
  ```python
  raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
  ```
- **Authorization Enforcement**: **NONE**.
- **SSRF Validation**: **NONE**.
- **Call Chain**: Instantiated by `continuous_scanner.py:65`, `main.py:144`, and `mcp_server.py:448`. When invoked via `main.py evaluate --target 10.0.0.1`, `DeterministicHarness` opens connections directly to the private target.

#### 2. `weaponizer.py` (`RQPWeaponizer`)
- **Socket Creation**: Line 38:
  ```python
  raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
  ```
- **Authorization Enforcement**: **NONE within class**.
- **SSRF Validation**: **NONE**.
- **Call Chain**: In `mcp_server.py:471`, the MCP handler calls `TargetAuthorizationGate.check_auth(...)`. However, `main.py:192` (`cmd_weaponize`) instantiates `RQPWeaponizer` directly without any gate checks or supervisor token verification. Any CLI user running `python main.py weaponize --target 169.254.169.254` fires dangling-byte exploits against cloud metadata!

#### 3. `engine/active_flaw_prober.py` (`ActiveFlawProber`)
- **Socket Creation**: Line 57:
  ```python
  raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
  ```
- **Authorization Enforcement**: **NONE**.
- **SSRF Validation**: **NONE**.
- **Call Chain**: Invoked by `continuous_scanner.py:230` and `rfc_hunt_swarm.py:2470`. Dispatches CL.TE, TE.CL, CL.0, and 36 TE obfuscation payloads to any host passed into constructor.

#### 4. `engine/differential_oracle.py` (`MultiImplementationDifferentialOracle`)
- **Socket Creation**: Line 55:
  ```python
  sock = socket.create_connection((target.host, target.port), timeout=target.timeout)
  ```
- **Authorization Enforcement**: **NONE**.
- **SSRF Validation**: **NONE**.
- **Call Chain**: `dispatch_single_target` transmits raw protocol probes to `target.host`. While default targets are `127.0.0.1:5006` and `127.0.0.1:8888`, `add_target(target)` allows inserting arbitrary `TargetEndpoint` objects pointing to any internal or external address.

#### 5. `protocol_ruler.py` (`ProtocolRuler`)
- **Socket Creation**: Line 109:
  ```python
  raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
  ```
- **Authorization Enforcement**: **DEFECTIVE**.
  Lines 92-93:
  ```python
  if host in ("0.0.0.0", "::"):
      raise ValueError(f"Target host cannot be {host} (INADDR_ANY listening address). Use 127.0.0.1 or localhost.")
  ```
  Only checks exact string matches for `"0.0.0.0"` and `"::"`.
- **SSRF Validation**: **NONE**.
- **Call Chain**: Invoked by `main.py:365` (`cmd_ruler`) and `rfc_hunt_swarm.py:2314`. Fired with oversized header probes (up to 64KB+) against any target IP.

#### 6. Auxiliary Raw Socket Callers
- `engine/delta_debugger.py:170`: `socket.create_connection((self.host, self.port))` — No check.
- `engine/sequence_engine.py:71, 292`: `socket.create_connection((host, port))` — No check.
- `engine/metamorphic_engine.py:165`: `socket.create_connection((host, port))` — No check.
- `rfc_hunt_swarm.py:2375`: `_sock.create_connection((t_host, t_port))` — Target liveness probe before spawning local `TestLabServer`.

---

## 3. Mathematical SSRF Validation & IP Range Invariant Analysis

Per `containment_ring_breakout_invariants.md` and `ORIGINAL_REQUEST.md:24`, all network targets must undergo mathematical IP range filtering using `ipaddress` parsing rather than naive string prefixes.

### Comprehensive IP Range Matrix

| Category | CIDR / Address Range | Standard / RFC | Python `ip.is_private` | Dedicated Network Invariant Check Required? | Rationale & Threat Model |
|---|---|---|---|---|---|
| **RFC 1918 (Private IPv4)** | `10.0.0.0/8`<br>`172.16.0.0/12`<br>`192.168.0.0/16` | RFC 1918 | `True` | `ip in ipaddress.ip_network(...)` | Prevents pivoting into internal corporate subnets, private management endpoints, and internal microservices. |
| **Loopback (IPv4/IPv6)** | `127.0.0.0/8`<br>`::1` | RFC 1122 / RFC 4291 | `True` (`is_loopback=True`) | `ip.is_loopback` | Blocked when scanning external targets (`allow_private=False`). Prevents attacking local daemons (Docker, Redis, local databases). |
| **Link-Local & Cloud Metadata** | `169.254.0.0/16`<br>`fe80::/10`<br>`169.254.169.254`<br>`fd00:ec2::254` | RFC 3927 / RFC 4291 | `True` (`is_link_local=True`) | **ALWAYS BLOCKED (even if `allow_private=True`)** | Prevents theft of cloud instance credentials, IAM role tokens, and AWS/GCP/Azure instance metadata. |
| **CGNAT (Carrier-Grade NAT)** | `100.64.0.0/10` | RFC 6598 | **`False` ⚠️** | **MANDATORY EXPLICIT CHECK**: `ip in ipaddress.ip_network("100.64.0.0/10")` | **CRITICAL GOTCHA**: Python `ipaddress` marks CGNAT as shared space, NOT private. Naive `ip.is_private` checks fail to block CGNAT. Attackers can hit internal cloud VPC transit gateways and container overlays. |
| **Unique Local IPv6 (ULA)** | `fc00::/7` | RFC 4193 | `True` | `ip in ipaddress.ip_network("fc00::/7")` | Blocks private IPv6 routing domains. |
| **Unspecified Address** | `0.0.0.0/8`<br>`::` | RFC 5735 / RFC 4291 | `True` (`is_unspecified=True`) | **ALWAYS BLOCKED** | INADDR_ANY bind address. Operating system socket stacks resolve `0.0.0.0` to localhost `127.0.0.1`. |
| **IPv4-Mapped IPv6** | `::ffff:0:0/96` | RFC 4291 §2.5.5.2 | Partial (depends on mapped IP) | **MANDATORY EXPLICIT CHECK**: `ip in ipaddress.ip_network("::ffff:0:0/96")` or `ip.ipv4_mapped` | Attackers wrap internal IPv4 addresses (e.g. `::ffff:127.0.0.1`, `::ffff:169.254.169.254`) in IPv6 notation to evade string filters. Dual-stack sockets unmap them to raw IPv4. |
| **Multicast & Reserved** | `224.0.0.0/4`<br>`ff00::/8`<br>`240.0.0.0/4` | RFC 5771 / RFC 1112 | Varies | `ip.is_multicast or ip.is_reserved` | Prevents local subnet flooding and broadcast amplification attacks. |
| **Documentation & Benchmarks** | `192.0.2.0/24`<br>`198.51.100.0/24`<br>`203.0.113.0/24`<br>`198.18.0.0/15`<br>`2001:db8::/32` | RFC 5737 / RFC 2544 | `False` in some versions | Explicit CIDR list | Non-routable blackhole addresses causing network socket hangs. |

### DNS Resolution & DNS Rebinding Invariants
When target hostnames (e.g. `target.example.com`, `my-service.internal`, `127.0.0.1.nip.io`) are supplied:
1. **Multi-Address Resolution**: `socket.getaddrinfo(hostname, None)` returns all IPv4 (`AF_INET`) and IPv6 (`AF_INET6`) addresses.
2. **Exhaustive Address Verification**: Every single resolved address must be evaluated. If **any** resolved IP falls into a blocked range, validation must immediately fail closed.
3. **DNS Rebinding (TOCTOU)**: If a hostname is validated at $T_0$, but resolved again by `socket.create_connection` at $T_1$, an attacker using a 0-TTL DNS record can return a public IP at $T_0$ and `127.0.0.1` or `169.254.169.254` at $T_1$. Therefore:
   - `validate_target_host` must return the validated IP address.
   - Probers should support connecting directly to the pinned IP while transmitting the target hostname in the HTTP `Host:` header and TLS SNI.

---

## 4. Current Test Suite Deficiencies in `tests/test_authorization_and_safety.py`

`tests/test_authorization_and_safety.py` currently contains only 8 unit tests:
1. `test_target_rejects_inaddr_any`: Tests only string matches for `0.0.0.0` and `::`.
2. `test_target_rejects_wildcard_bypass`: Tests only `*` and `all`.
3. `test_target_enforces_whitelist`: Tests only `unauthorized-victim.example.com`.
4. `test_payload_length_enforcement`: Tests 64KB boundary.
5. `test_sliding_window_rate_limiter`: Tests 60 req/min rate limiter.
6. `test_supervisor_token_enforcement`: Tests `RFCHUNT_SUPERVISOR_TOKEN`.
7. `test_mcp_error_sanitization`: Tests MCP error formatting.
8. `test_database_defensive_intelligence_population`: Tests database seeding.

### Identified Test Gaps:
- ❌ No test for RFC1918 IPv4 blocking (`10.0.0.1`, `172.16.0.1`, `192.168.1.1`).
- ❌ No test for Link-Local / Cloud Metadata blocking (`169.254.169.254`, `fe80::1`).
- ❌ No test for CGNAT blocking (`100.64.0.1`).
- ❌ No test for Unique Local IPv6 blocking (`fc00::1`, `fd00::1`).
- ❌ No test for IPv4-mapped IPv6 blocking (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`).
- ❌ No test for DNS rebinding / resolution to private IP.
- ❌ No test verifying that probers (`DeterministicHarness`, `RQPWeaponizer`, `ProtocolRuler`, etc.) fail closed when given an unauthorized or private target.
- ❌ No test asserting that CLI does not auto-whitelist arbitrary hosts.

---

## 5. Architectural Remediation Blueprint

To remediate Milestone 4 with 100% adherence to project invariants:

### Step 1: Create `engine/safe_network_validator.py`
Implement the mathematical validator conforming to the contract specified in `PROJECT.md:60-64`:
- `is_safe_target_ip(ip_str: str) -> bool`
- `validate_target_host(target: str, allow_private: bool = False) -> Tuple[bool, str]`
- `is_cloud_metadata(ip: ipaddress._BaseAddress) -> bool`

### Step 2: Remediate CLI Target Authorization in `rfc_hunt_swarm.py:2268-2276`
Remove the unconditional `TargetAuthorizationGate.authorize_target(t_host)` call!
Validate each target against both `validate_target_host` (SSRF guard) and `TargetAuthorizationGate.validate_target` (authorization whitelist).

### Step 3: Harden `TargetAuthorizationGate` in `mcp_server.py`
- In `authorize_target(host)`: reject cloud metadata (`169.254.0.0/16`), unspecified (`0.0.0.0`), and run SSRF check.
- In `check_target(host)`: execute `validate_target_host(host, allow_private=is_local)`.
- In `get_allowed_targets()`: sanitize `RFCHUNT_AUTHORIZED_TARGETS` to ensure no cloud metadata or unspecified addresses are admitted.

### Step 4: Enforce Fail-Closed Gates Across All Raw Socket Probers
In `deterministic_harness.py`, `weaponizer.py`, `engine/active_flaw_prober.py`, `engine/differential_oracle.py`, and `protocol_ruler.py`:
- In `__init__` / connection methods, validate target host against `TargetAuthorizationGate` and `SafeNetworkValidator`.
- If unauthorized or SSRF target, raise `PermissionError` or `ValueError` before calling `socket.create_connection`.

### Step 5: Expand `tests/test_authorization_and_safety.py`
Add dedicated unit and integration tests covering:
- Mathematical rejection of each blocked IP range.
- Verification that Cloud Metadata is rejected even if `allow_private=True`.
- Verification of CGNAT `100.64.0.0/10` rejection.
- Verification of IPv4-mapped IPv6 rejection.
- DNS resolution checks (mocking or using test hosts).
- Prober fail-closed verification on unauthorized targets.

---

## 6. Concrete Code Proposals

### Proposed `engine/safe_network_validator.py`
```python
"""
Safe Network Validator: Mathematical SSRF & Destination Safety Verification.
Enforces multi-ring containment invariants against private, loopback, link-local,
cloud metadata, CGNAT, unspecified, and IPv4-mapped IPv6 network ranges.
"""

import ipaddress
import re
import socket
from typing import List, Optional, Set, Tuple, Union

# Blocked IPv4 Network Ranges
BLOCKED_IPV4_NETWORKS: List[ipaddress.IPv4Network] = [
    ipaddress.ip_network("0.0.0.0/8"),          # Unspecified / This host (RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # CGNAT Shared Address Space (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / Cloud Metadata (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
]

# Blocked IPv6 Network Ranges
BLOCKED_IPV6_NETWORKS: List[ipaddress.IPv6Network] = [
    ipaddress.ip_network("::/128"),             # Unspecified (RFC 4291)
    ipaddress.ip_network("::1/128"),            # Loopback (RFC 4291)
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6 (RFC 4291)
    ipaddress.ip_network("64:ff9b::/96"),       # IPv4/IPv6 translation (RFC 6052)
    ipaddress.ip_network("100::/64"),           # Discard prefix (RFC 6666)
    ipaddress.ip_network("2001:db8::/32"),      # Documentation (RFC 3849)
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address ULA (RFC 4193)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast (RFC 4291)
    ipaddress.ip_network("ff00::/8"),           # Multicast (RFC 4291)
]

CLOUD_METADATA_IPS: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = {
    ipaddress.ip_address("169.254.169.254"),    # AWS IMDSv1/v2, GCP, Azure, OpenStack
    ipaddress.ip_address("fd00:ec2::254"),      # AWS IPv6 IMDS
}


def _clean_host(target: str) -> str:
    cleaned = target.strip()
    cleaned = re.sub(r"^https?://", "", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.split("/")[0]
    if cleaned.startswith("[") and "]" in cleaned:
        cleaned = cleaned[1:cleaned.index("]")]
    elif ":" in cleaned:
        cleaned = cleaned.split(":", 1)[0]
    return cleaned.strip().lower()


def is_cloud_metadata(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Returns True if the address is a link-local or known cloud metadata endpoint."""
    if ip in CLOUD_METADATA_IPS:
        return True
    if isinstance(ip, ipaddress.IPv4Address):
        return ip in ipaddress.ip_network("169.254.0.0/16")
    elif isinstance(ip, ipaddress.IPv6Address):
        return ip in ipaddress.ip_network("fe80::/10") or ip.is_link_local
    return False


def is_safe_target_ip(ip_str: str) -> bool:
    """
    Mathematical verification of an IP string against all blocked network ranges.
    Returns True ONLY if the IP is a routable, non-reserved public address.
    """
    try:
        cleaned = _clean_host(ip_str)
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        return False

    if is_cloud_metadata(ip):
        return False

    if isinstance(ip, ipaddress.IPv4Address):
        for net in BLOCKED_IPV4_NETWORKS:
            if ip in net:
                return False
        if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            return False
    elif isinstance(ip, ipaddress.IPv6Address):
        # IPv4-mapped IPv6 check
        if ip.ipv4_mapped is not None or ip in ipaddress.ip_network("::ffff:0:0/96"):
            return False
        for net in BLOCKED_IPV6_NETWORKS:
            if ip in net:
                return False
        if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            return False

    return True


def validate_target_host(target: str, allow_private: bool = False) -> Tuple[bool, str]:
    """
    Validates a target hostname or IP address.
    If allow_private is True, loopback and private RFC1918 are permitted (for local test lab),
    but Cloud Metadata, Unspecified (0.0.0.0), and IPv4-mapped IPv6 remain strictly forbidden.
    """
    host = _clean_host(target)
    if not host or host in ("0.0.0.0", "::", "*", "all"):
        return False, f"Target '{target}' is an invalid or unspecified destination address."

    # Try evaluating as IP literal
    try:
        ip = ipaddress.ip_address(host)
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False

    if is_ip_literal:
        if is_cloud_metadata(ip):
            return False, f"Target IP {host} is in cloud metadata / link-local range, strictly blocked."
        if ip.is_unspecified:
            return False, f"Target IP {host} is INADDR_ANY listening address, invalid scan destination."
        if isinstance(ip, ipaddress.IPv6Address) and (ip.ipv4_mapped is not None or ip in ipaddress.ip_network("::ffff:0:0/96")):
            return False, f"Target IP {host} is an IPv4-mapped IPv6 address, strictly blocked."

        if not allow_private:
            if not is_safe_target_ip(host):
                return False, f"Target IP {host} is in private, loopback, or reserved range, blocked without explicit private authorization."
        return True, f"Target IP {host} is safe."

    # Hostname: Check localhost
    if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost"):
        if not allow_private:
            return False, f"Target hostname '{host}' resolves to loopback, blocked without explicit private authorization."
        return True, f"Target '{host}' is authorized for local private testing."

    # DNS Resolution & Rebinding Check
    try:
        addr_info = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        return False, f"DNS resolution failed for target hostname '{host}': {e}"

    if not addr_info:
        return False, f"Target hostname '{host}' resolved to 0 IP addresses."

    for item in addr_info:
        sockaddr = item[4]
        ip_addr_str = sockaddr[0]
        try:
            resolved_ip = ipaddress.ip_address(ip_addr_str)
        except ValueError:
            return False, f"Host '{host}' resolved to invalid IP address: {ip_addr_str}"

        if is_cloud_metadata(resolved_ip):
            return False, f"Host '{host}' resolved to cloud metadata IP {ip_addr_str}, strictly blocked."
        if resolved_ip.is_unspecified:
            return False, f"Host '{host}' resolved to unspecified address {ip_addr_str}, invalid destination."
        if isinstance(resolved_ip, ipaddress.IPv6Address) and (resolved_ip.ipv4_mapped is not None or resolved_ip in ipaddress.ip_network("::ffff:0:0/96")):
            return False, f"Host '{host}' resolved to IPv4-mapped IPv6 address {ip_addr_str}, strictly blocked."

        if not allow_private:
            if not is_safe_target_ip(ip_addr_str):
                return False, f"Host '{host}' resolved to private/reserved IP {ip_addr_str} (DNS rebinding / SSRF violation)."

    return True, f"Target hostname '{host}' successfully verified against SSRF invariants."
```

### Proposed Remediation in `rfc_hunt_swarm.py:2268-2276`
```python
    # Authorize and validate each target host specified on the CLI
    from mcp_server import TargetAuthorizationGate
    from engine.safe_network_validator import validate_target_host
    for t_host, t_port, t_tls in target_list:
        is_local = t_host in ("127.0.0.1", "localhost", "::1", "[::1]")
        
        # 1. Mathematical SSRF Verification
        is_safe_net, net_reason = validate_target_host(t_host, allow_private=is_local)
        if not is_safe_net:
            print(f"[!] Target SSRF validation error for {t_host}: {net_reason}")
            sys.exit(1)

        # 2. Authorization Whitelist Gate (NO auto-whitelisting)
        is_valid_target, target_reason = TargetAuthorizationGate.validate_target(t_host)
        if not is_valid_target:
            print(f"[!] Target authorization error for {t_host}: {target_reason}")
            sys.exit(1)
```

---

## 7. Conclusion

The investigation successfully documented the complete causal chain from CLI auto-whitelisting to ungated prober execution and missing mathematical SSRF verification. The proposed architecture guarantees zero-touch environment compliance, full containment invariance, and fail-closed security gating across the HTTP Terminator swarm.
