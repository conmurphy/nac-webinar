"""
A BD subnet's gateway must be a usable host address.

Catches gateways set to the network address, the broadcast address, or a /31 or
/32 that cannot host a gateway plus endpoints. These are wrong regardless of
naming convention or allocation policy, so they belong in the local tier.

Deliberately does NOT check whether the subnet is in the tenant's allocated
range - that is organisational policy and lives in the pipeline tier.

ASSUMED DATA MODEL
    apic.tenants[].bridge_domains[].name
    apic.tenants[].bridge_domains[].subnets[].ip
"""

import ipaddress

# A gateway needs at least one other usable address for an endpoint, so /31 and
# /32 are rejected for BD subnets. Raise this if you legitimately use /31s.
MIN_USABLE_PREFIX = 30


class Rule:
    id = "104"
    description = "BD subnet gateway must be a usable host address"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        tenants = (data.get("apic") or {}).get("tenants") or []

        for t_idx, tenant in enumerate(tenants):
            for b_idx, bd in enumerate(tenant.get("bridge_domains") or []):
                bd_name = bd.get("name", "?")

                for s_idx, subnet in enumerate(bd.get("subnets") or []):
                    ip = subnet.get("ip", "")
                    loc = (f"apic.tenants[{t_idx}].bridge_domains[{b_idx}]"
                           f".subnets[{s_idx}]")
                    try:
                        iface = ipaddress.ip_interface(ip)
                    except (ValueError, TypeError):
                        continue  # reported by the consistency rule

                    net = iface.network

                    if net.prefixlen > MIN_USABLE_PREFIX:
                        results.append(
                            f"{loc} - BD '{bd_name}' subnet {ip} is a /"
                            f"{net.prefixlen}; too small for a gateway plus "
                            f"endpoints (minimum /{MIN_USABLE_PREFIX})"
                        )
                        continue

                    if iface.ip == net.network_address:
                        results.append(
                            f"{loc} - BD '{bd_name}' gateway {iface.ip} is the "
                            f"network address of {net}, not a usable host address"
                        )
                    elif iface.ip == net.broadcast_address:
                        results.append(
                            f"{loc} - BD '{bd_name}' gateway {iface.ip} is the "
                            f"broadcast address of {net}, not a usable host "
                            f"address"
                        )

        return results