## 2026-10-18T21:31:25Z
# Dispatch: Challenger M4-1 (SSRF Adversarial Fuzzing)

**Role**: Challenger M4-1 (SSRF Adversarial Fuzzing)
**Working Directory**: `D:\harfile\rfchunt\.agents\teamwork\challenger_m4_1`

## Read:
- `D:\harfile\rfchunt\.agents\teamwork\ORIGINAL_REQUEST.md`
- `D:\harfile\rfchunt\.agents\teamwork\orchestrator_1\PROJECT.md`
- `D:\harfile\rfchunt\.agents\teamwork\worker_m4\handoff.md`

## Mission:
Empirically challenge the new mathematical SSRF validator (`engine/safe_network_validator.py`) and gated probers:
1. Craft adversarial IP representations:
   - Dotted decimal variations (0177.0.0.1, 0x7f.1, 2130706433, 0x7f000001)
   - IPv4-mapped IPv6 (::ffff:127.0.0.1, ::ffff:169.254.169.254, ::ffff:10.0.0.1, ::ffff:100.64.0.1)
   - IPv6 ULA (fc00::1, fd12:3456:789a::1)
   - Cloud metadata (169.254.169.254, fe80::1, fd00:ec2::254)
   - Carrier-Grade NAT (100.64.0.1, 100.127.255.254)
   - Unspecified (0.0.0.0, 0.0.0.0/8, ::)
   - DNS rebinding scenarios (domain resolving to multiple IPs where one is private/metadata)
2. Assert that `validate_target_host(ip)` strictly rejects all of these (returning `False, reason`).
3. Assert that all 5 probers (`DeterministicHarness`, `RQPWeaponizer`, `ActiveFlawProber`, `MultiImplementationDifferentialOracle`, `ProtocolRuler`) fail closed without opening socket connections to these addresses.
4. Verify that the CLI in `rfc_hunt_swarm.py` strictly rejects unauthorized / SSRF targets without auto-whitelisting them.
5. Deliver verdict: APPROVE or REQUEST_CHANGES in `handoff.md` and message orchestrator.

