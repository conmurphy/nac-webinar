# -*- coding: utf-8 -*-
"""
Validation Rule 04: BD name / subnet consistency

For a bridge domain named x.x.x.x_<mask>:
  1. The name must be a valid network address for that mask
     (198.18.194.1_27 is invalid - .1 is not a /27 boundary).
  2. Every subnet's mask must equal the mask in the name.
  3. The gateway must be the first usable host (network + 1).

Requires real IP arithmetic, so it cannot be expressed as an ND compliance
template - this is exactly the class of check that belongs pre-commit.
"""

import ipaddress

from nac_validate import RuleBase, Violation


def _split_name(name):
    """'198.18.194.160_27' -> ('198.18.194.160', 27) or (None, None)."""
    if not isinstance(name, str) or "_" not in name:
        return None, None
    base, _, mask = name.rpartition("_")
    try:
        return base, int(mask)
    except ValueError:
        return None, None


class Rule(RuleBase):
    id = "04"
    description = (
        "Verify BD name matches its subnet mask and gateway is the first usable host"
    )
    severity = "HIGH"
    title = "BD name / subnet mismatch"
    explanation = (
        "Bridge domains should be named after the subnet and contain a corresponding gateway"
    )
    recommendation = (
        "Rename the BD to match the subnet, or correct the subnet so its network "
        "address, mask and gateway (.network + 1) agree with the name."
    )
    affected_items_label = "Inconsistent bridge domains"

    @classmethod
    def match(cls, data):
        violations = []
        tenants = (data.get("apic") or {}).get("tenants") or []

        for tenant in tenants:
            tname = tenant.get("name")
            for bd in tenant.get("bridge_domains") or []:
                bd_name = bd.get("name")
                path = f"apic.tenants[{tname}].bridge_domains[{bd_name}]"
                base, mask = _split_name(bd_name)

                if base is None:
                    violations.append(
                        Violation(
                            message=(
                                f"{path} - name does not follow the "
                                f"x.x.x.x_<mask> convention"
                            ),
                            path=path,
                        )
                    )
                    continue

                # 1. name must be a valid network boundary
                try:
                    strict_net = ipaddress.ip_network(f"{base}/{mask}", strict=True)
                except ValueError:
                    violations.append(
                        Violation(
                            message=(
                                f"{path} - {base}/{mask} is not a valid network "
                                f"address for a /{mask} (host bits are set)"
                            ),
                            path=path,
                        )
                    )
                    continue

                subnets = bd.get("subnets") or []
                if not subnets:
                    violations.append(
                        Violation(
                            message=f"{path} - BD has no subnets defined",
                            path=path,
                        )
                    )
                    continue

                expected_gw = strict_net.network_address + 1

                for subnet in subnets:
                    ip_str = subnet.get("ip")
                    try:
                        iface = ipaddress.ip_interface(ip_str)
                    except (ValueError, TypeError):
                        violations.append(
                            Violation(
                                message=f"{path}.subnets - '{ip_str}' is not a "
                                        f"valid address/mask",
                                path=f"{path}.subnets",
                            )
                        )
                        continue

                    # 2. mask must match the name
                    if iface.network.prefixlen != mask:
                        violations.append(
                            Violation(
                                message=(
                                    f"{path}.subnets - name says /{mask} but "
                                    f"subnet {ip_str} is a /"
                                    f"{iface.network.prefixlen}"
                                ),
                                path=f"{path}.subnets",
                                details=f"expected /{mask}",
                            )
                        )
                        continue

                    # 3. gateway must be first usable host
                    if iface.ip != expected_gw:
                        violations.append(
                            Violation(
                                message=(
                                    f"{path}.subnets - gateway {iface.ip} is not "
                                    f"the first usable host of {strict_net} "
                                    f"(expected {expected_gw})"
                                ),
                                path=f"{path}.subnets",
                                details=f"expected {expected_gw}/{mask}",
                            )
                        )

        return violations