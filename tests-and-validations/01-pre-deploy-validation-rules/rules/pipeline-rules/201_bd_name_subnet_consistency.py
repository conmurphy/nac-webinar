"""
A bridge domain's name must encode the subnet it actually carries.

WHY THIS RULE EXISTS
    BD-198.18.215.128_26 carrying subnet 198.18.21.129/26 passes every other
    check: the BD name is in range, the mask matches the name suffix, and the
    address is syntactically valid. Only comparing the name against the subnet
    catches the dropped digit.


LOCAL TIER
    Self-consistency, not policy - a mismatch is wrong in any tenant, so this is
    safe to block a commit on. Pure string/CIDR work, no I/O.

ASSUMED DATA MODEL
    apic.tenants[].name
    apic.tenants[].bridge_domains[].name          e.g. "198.18.215.128_26"
    apic.tenants[].bridge_domains[].subnets[].ip  e.g. "198.18.215.129/26"
"""

import ipaddress


class Rule:
    id = "201"
    description = "BD name must match the subnet it carries"
    severity = "HIGH"

    # A BD name is only checked when it looks like <network>_<mask>. Names that
    # do not follow the convention are reported by the naming rule, not here -
    # one fault should produce one finding.
    @staticmethod
    def _implied_network(bd_name):
        if "_" not in bd_name:
            return None
        addr, _, mask = bd_name.rpartition("_")
        if not mask.isdigit():
            return None
        try:
            return ipaddress.ip_network(f"{addr}/{mask}", strict=False)
        except ValueError:
            return None

    @classmethod
    def match(cls, data):
        results = []
        tenants = (data.get("apic") or {}).get("tenants") or []

        for t_idx, tenant in enumerate(tenants):
            t_name = tenant.get("name", f"index-{t_idx}")

            for b_idx, bd in enumerate(tenant.get("bridge_domains") or []):
                bd_name = bd.get("name", "")
                implied = cls._implied_network(bd_name)
                if implied is None:
                    continue  # not a subnet-style name; other rules cover it

                subnets = bd.get("subnets") or []
                if not subnets:
                    continue  # coverage is a separate rule

                for s_idx, subnet in enumerate(subnets):
                    ip = subnet.get("ip", "")
                    try:
                        iface = ipaddress.ip_interface(ip)
                    except (ValueError, TypeError):
                        results.append(
                            f"apic.tenants[{t_idx}].bridge_domains[{b_idx}]"
                            f".subnets[{s_idx}] - '{ip}' is not a valid "
                            f"address/prefix (tenant {t_name}, BD {bd_name})"
                        )
                        continue

                    if iface.network != implied:
                        results.append(
                            f"apic.tenants[{t_idx}].bridge_domains[{b_idx}]"
                            f".subnets[{s_idx}] - BD name '{bd_name}' implies "
                            f"{implied}, but the subnet is {ip} "
                            f"(network {iface.network}). Name and subnet must "
                            f"agree - check for a mistyped octet."
                        )

        return results