# -*- coding: utf-8 -*-
"""
Validation Rule 403: UCS domain coverage on static ports

Every EPG with static port bindings must bind to ALL required UCS domains.
This is a cardinality/"at least one of each" check - the exact class of rule
that template-based compliance struggles with, and that belongs pre-commit.

Also verifies each domain has BOTH fabric-interconnect sides (A and B).
"""

from nac_validate import RuleBase, Violation

# Substring that identifies each UCS domain in the port-channel name.
REQUIRED_UCS_DOMAINS = {
    "prod": "ucs-prod-01",
    "test": "ucs-test-01",
    "sandbox": "ucs-sandbox-01",
}

# Expected fabric interconnect sides per domain.
REQUIRED_SIDES = ("-A", "-B")

# EPGs (tenant, epg) that intentionally skip a domain.
DOMAIN_EXEMPTIONS = {
    ("shared-services", "198.18.194.160_27"): {"prod"},  # nutanix clusters: test+sandbox only
}


class Rule(RuleBase):
    id = "204"
    description = "Verify EPG static ports cover all required UCS domains (A and B)"
    severity = "HIGH"
    title = "Incomplete UCS domain coverage"
    explanation = (
        "Each network segment must be trunked to every UCS domain so workloads "
        "can be placed on any compute pool. A missing domain means VMs on that "
        "pool silently have no connectivity for this VLAN."
    )
    recommendation = (
        "Add static_ports entries for the missing domain/side, or record a "
        "deliberate exception in DOMAIN_EXEMPTIONS."
    )
    affected_items_label = "EPGs missing domains"

    @classmethod
    def match(cls, data):
        violations = []
        tenants = (data.get("apic") or {}).get("tenants") or []

        for tenant in tenants:
            tname = tenant.get("name")
            for ap in tenant.get("application_profiles") or []:
                apname = ap.get("name")
                for epg in ap.get("endpoint_groups") or []:
                    epg_name = epg.get("name")
                    static_ports = epg.get("static_ports") or []
                    if not static_ports:
                        continue  # EPGs with no static ports are out of scope

                    path = (
                        f"apic.tenants[{tname}].application_profiles[{apname}]"
                        f".endpoint_groups[{epg_name}].static_ports"
                    )
                    channels = [
                        sp.get("channel", "") for sp in static_ports
                    ]
                    exempt = DOMAIN_EXEMPTIONS.get((tname, epg_name), set())

                    for dom, marker in REQUIRED_UCS_DOMAINS.items():
                        if dom in exempt:
                            continue
                        matching = [c for c in channels if marker in c]
                        if not matching:
                            violations.append(
                                Violation(
                                    message=(
                                        f"{path} - missing static port binding to "
                                        f"the '{dom}' UCS domain ({marker})"
                                    ),
                                    path=path,
                                    details=f"present: {sorted(set(channels))}",
                                )
                            )
                            continue

                        # both FI sides present?
                        for side in REQUIRED_SIDES:
                            if not any(c.endswith(side) for c in matching):
                                violations.append(
                                    Violation(
                                        message=(
                                            f"{path} - '{dom}' UCS domain is bound "
                                            f"but side {side.lstrip('-')} is "
                                            f"missing"
                                        ),
                                        path=path,
                                        details=f"present: {sorted(matching)}",
                                    )
                                )

        return violations