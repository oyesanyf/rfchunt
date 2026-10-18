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
    cleaned = cleaned.split("/")[0].strip()
    if cleaned.startswith("[") and "]" in cleaned:
        cleaned = cleaned[1:cleaned.index("]")]
    elif cleaned.count(":") == 1:
        cleaned = cleaned.split(":", 1)[0]
    return cleaned.strip().lower()


def is_cloud_metadata(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Returns True if the address is a link-local or known cloud metadata endpoint."""
    if ip in CLOUD_METADATA_IPS:
        return True
    if isinstance(ip, ipaddress.IPv4Address):
        return ip in ipaddress.ip_network("169.254.0.0/16") or ip.is_link_local
    elif isinstance(ip, ipaddress.IPv6Address):
        return ip in ipaddress.ip_network("fe80::/10") or ip.is_link_local
    return False


def is_safe_target_ip(ip_str: str, allow_private: bool = False) -> bool:
    """
    Mathematical verification of an IP string against all blocked network ranges.
    Returns True ONLY if the IP is a safe, valid destination address.
    If allow_private=True, loopback and private ranges are permitted, but
    cloud metadata, unspecified, and IPv4-mapped IPv6 remain strictly forbidden.
    """
    try:
        cleaned = _clean_host(ip_str)
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        return False

    if is_cloud_metadata(ip):
        return False

    if ip.is_unspecified:
        return False

    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None or ip in ipaddress.ip_network("::ffff:0:0/96"):
            return False

    if allow_private:
        # Loopback is explicitly permitted for local testing
        if ip.is_loopback:
            return True
        # Private subnets are permitted, but multicast, reserved, and broadcast are not
        if ip.is_multicast or ip.is_reserved:
            return False
        return True

    # allow_private is False: strictly block all private, loopback, CGNAT, and reserved subnets
    if isinstance(ip, ipaddress.IPv4Address):
        for net in BLOCKED_IPV4_NETWORKS:
            if ip in net:
                return False
        if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            return False
    elif isinstance(ip, ipaddress.IPv6Address):
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
            if not is_safe_target_ip(host, allow_private=False):
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
            if not is_safe_target_ip(ip_addr_str, allow_private=False):
                return False, f"Host '{host}' resolved to private/reserved IP {ip_addr_str} (DNS rebinding / SSRF violation)."

    return True, f"Target hostname '{host}' successfully verified against SSRF invariants."
