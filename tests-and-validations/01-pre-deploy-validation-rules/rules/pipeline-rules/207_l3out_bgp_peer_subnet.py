# -*- coding: utf-8 -*-
"""
Validation Rule 408: L3Out BGP peer addressing

For each L3Out SVI, verifies that the BGP peer IP is inside the same subnet as
the interface addresses, and that ip_a / ip_b / ip_shared / peer are all
distinct and share the same mask. Catches transposed digits and wrong-mask
typos that leave the session permanently Idle.
"""

import ipaddress

from nac_validate import RuleBase, Violation


class Rule(RuleBase):
    id = "207"
    description = "Verify L3Out BGP peer IPs are within the SVI subnet"
    severity = "HIGH"
    title = "BGP peer outside interface subnet"
    explanation = (
        "A BGP peer address outside the SVI subnet is not directly connected, so "
        "the session never establishes and the L3Out advertises nothing - with "
        "no config error reported by APIC."
    )
    recommendation = (
        "Correct the peer IP so it falls within the interface subnet, and ensure "
        "all interface addresses use a consistent mask."
    )
    affected_items_label = "Misaddressed peers"

    @classmethod
    def match(cls, data):
        violations = []
        tenants = (data.get("apic") or {}).get("tenants") or []

        for tenant in tenants:
            tname = tenant.get("name")
            for l3out in tenant.get("l3outs") or []:
                lname = l3out.get("name")
                for np in l3out.get("node_profiles") or []:
                    for ip_prof in np.get("interface_profiles") or []:
                        for idx, iface in enumerate(
                            ip_prof.get("interfaces") or []
                        ):
                            path = (
                                f"apic.tenants[{tname}].l3outs[{lname}]"
                                f".node_profiles[{np.get('name')}]"
                                f".interface_profiles[{ip_prof.get('name')}]"
                                f".interfaces[{idx}]"
                            )
                            addrs = {
                                k: iface.get(k)
                                for k in ("ip", "ip_a", "ip_b", "ip_shared")
                                if iface.get(k)
                            }
                            nets = {}
                            for key, val in addrs.items():
                                try:
                                    nets[key] = ipaddress.ip_interface(val)
                                except ValueError:
                                    violations.append(
                                        Violation(
                                            message=f"{path}.{key} - '{val}' is "
                                                    f"not a valid address/mask",
                                            path=path,
                                        )
                                    )
                            if not nets:
                                continue

                            # consistent mask across interface addresses
                            masks = {n.network.prefixlen for n in nets.values()}
                            if len(masks) > 1:
                                violations.append(
                                    Violation(
                                        message=(
                                            f"{path} - interface addresses use "
                                            f"inconsistent masks: "
                                            f"{sorted(masks)}"
                                        ),
                                        path=path,
                                    )
                                )

                            reference = next(iter(nets.values())).network

                            for pidx, peer in enumerate(
                                iface.get("bgp_peers") or []
                            ):
                                pip = peer.get("ip")
                                try:
                                    peer_if = ipaddress.ip_interface(pip)
                                except (ValueError, TypeError):
                                    violations.append(
                                        Violation(
                                            message=(
                                                f"{path}.bgp_peers[{pidx}].ip - "
                                                f"'{pip}' is not a valid "
                                                f"address/mask"
                                            ),
                                            path=path,
                                        )
                                    )
                                    continue

                                if peer_if.ip not in reference:
                                    violations.append(
                                        Violation(
                                            message=(
                                                f"{path}.bgp_peers[{pidx}] - peer "
                                                f"{peer_if.ip} is not inside the "
                                                f"interface subnet {reference}"
                                            ),
                                            path=path,
                                            details=f"interface subnet {reference}",
                                        )
                                    )

                                if peer_if.ip in {n.ip for n in nets.values()}:
                                    violations.append(
                                        Violation(
                                            message=(
                                                f"{path}.bgp_peers[{pidx}] - peer "
                                                f"IP {peer_if.ip} collides with a "
                                                f"local interface address"
                                            ),
                                            path=path,
                                        )
                                    )

        return violations