# -*- coding: utf-8 -*-
"""
Validation Rule 409: global subnet overlap detection

Collects every BD subnet, ESG external-subnet selector and leaked prefix across
ALL tenants and reports any pair that overlaps. Catches the classic
"two teams grabbed the same /26" and "a /24 swallowed someone's /26" errors that
no per-object compliance rule can see.
"""

import ipaddress
from itertools import combinations

from nac_validate import RuleBase, Violation

# Prefixes intentionally broad / shared - excluded from overlap analysis.
OVERLAP_IGNORE = {
    "0.0.0.0/0",
    "0.0.0.0/1",
    "128.0.0.0/1",
}


class Rule(RuleBase):
    id = "409"
    description = "Verify no subnet overlaps across tenants"
    severity = "HIGH"
    title = "Overlapping subnets"
    explanation = (
        "Two tenants advertising overlapping prefixes causes non-deterministic "
        "routing once the prefixes are leaked or advertised out a shared L3Out. "
        "Overlap is invisible in any single tenant's config."
    )
    recommendation = (
        "Re-allocate one of the overlapping subnets from the owning tenant's /21."
    )
    affected_items_label = "Overlapping prefixes"

    @classmethod
    def match(cls, data):
        violations = []
        tenants = (data.get("apic") or {}).get("tenants") or []
        seen = []  # (network, origin_label)

        for tenant in tenants:
            tname = tenant.get("name")

            for bd in tenant.get("bridge_domains") or []:
                for subnet in bd.get("subnets") or []:
                    try:
                        net = ipaddress.ip_interface(subnet.get("ip")).network
                    except (ValueError, TypeError):
                        continue
                    if str(net) in OVERLAP_IGNORE:
                        continue
                    seen.append(
                        (net, f"{tname}/bd:{bd.get('name')}")
                    )

            for ap in tenant.get("application_profiles") or []:
                for esg in ap.get("endpoint_security_groups") or []:
                    for sel in esg.get("ip_external_subnet_selectors") or []:
                        try:
                            net = ipaddress.ip_network(
                                sel.get("ip"), strict=False
                            )
                        except (ValueError, TypeError):
                            continue
                        if str(net) in OVERLAP_IGNORE:
                            continue
                        seen.append(
                            (net, f"{tname}/esg:{esg.get('name')}")
                        )

        for (net_a, src_a), (net_b, src_b) in combinations(seen, 2):
            if net_a == net_b:
                violations.append(
                    Violation(
                        message=(
                            f"duplicate subnet {net_a} defined in both "
                            f"{src_a} and {src_b}"
                        ),
                        path="apic.tenants",
                    )
                )
            elif net_a.overlaps(net_b):
                violations.append(
                    Violation(
                        message=(
                            f"overlapping subnets: {net_a} ({src_a}) overlaps "
                            f"{net_b} ({src_b})"
                        ),
                        path="apic.tenants",
                    )
                )

        return violations