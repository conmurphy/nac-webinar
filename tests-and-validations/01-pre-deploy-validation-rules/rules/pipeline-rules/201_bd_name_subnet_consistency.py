"""
A bridge domain's name must encode the subnet it actually carries.
"""

import ipaddress

from nac_validate import RuleBase, Violation


class Rule(RuleBase):
    id = "201"
    description = "BD name must match the associated subnet"
    severity = "HIGH"

    title = "Inconsistent bridge domains name and subnet"
    affected_items_label = "Inconsistent bridge domains"

    explanation = """\
Our policy is such that bridge domains are named after their respective subnet, so the name is the primary
index engineers and tooling use to find a segment. """

    recommendation = """\
Decide which value is correct, then make the other agree.

If the BD name is right, fix the subnet:

  bridge_domains:
    - name: 198.18.215.128_26
      subnets:
        - ip: 198.18.215.129/26     # e.g. was 198.18.21.129/26

If the subnet is right, rename the BD and every reference to it - the EPG name,
the EPG's bridge_domain reference, and any ESG selectors.

The gateway should be the first usable host of the named network: for
198.18.215.128/26 that is 198.18.215.129."""

    @staticmethod
    def _implied_network(bd_name):
        """
        '198.18.215.128_26' -> IPv4Network('198.18.215.128/26')

        Returns None when the name does not follow the convention; the naming
        rule reports that, so one fault produces one finding.
        """
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
        violations = []
        tenants = (data.get("apic") or {}).get("tenants") or []

        for tenant in tenants:
            t_name = tenant.get("name", "?")

            for bd in tenant.get("bridge_domains") or []:
                bd_name = bd.get("name", "")
                implied = cls._implied_network(bd_name)
                if implied is None:
                    continue

                subnets = bd.get("subnets") or []
                if not subnets:
                    continue  # subnet coverage is a separate rule

                for subnet in subnets:
                    ip = subnet.get("ip", "")
                    base = (f"apic.tenants[name={t_name}]"
                            f".bridge_domains[name={bd_name}]"
                            f".subnets[{ip}]")

                    try:
                        iface = ipaddress.ip_interface(ip)
                    except (ValueError, TypeError):
                        violations.append(Violation(
                            message=(f"'{ip}' is not a valid address/prefix"),
                            path=base,
                            details={"tenant": t_name, "bd": bd_name,
                                     "subnet": ip},
                        ))
                        continue

                    expected_gw = implied.network_address + 1

                    if iface.network != implied:
                        violations.append(Violation(
                            message=(f"BD name '{bd_name}' implies {implied}, "
                                     f"but the subnet is {ip} (network "
                                     f"{iface.network}). Expected gateway "
                                     f"{expected_gw} - check for a mistyped "
                                     f"octet"),
                            path=base,
                            details={
                                "tenant": t_name,
                                "bd": bd_name,
                                "implied_network": str(implied),
                                "configured_subnet": ip,
                                "configured_network": str(iface.network),
                                "expected_gateway": str(expected_gw),
                            },
                        ))
                    elif iface.ip != expected_gw:
                        violations.append(Violation(
                            message=(f"gateway {iface.ip} is not the first "
                                     f"usable host of {implied} (expected "
                                     f"{expected_gw})"),
                            path=base,
                            details={
                                "tenant": t_name,
                                "bd": bd_name,
                                "configured_gateway": str(iface.ip),
                                "expected_gateway": str(expected_gw),
                            },
                        ))

        return violations