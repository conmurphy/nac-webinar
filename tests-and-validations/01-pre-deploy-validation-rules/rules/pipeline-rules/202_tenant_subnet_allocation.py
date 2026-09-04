# -*- coding: utf-8 -*-
"""
Validation Rule 400: Tenant subnet allocation

Every bridge domain / EPG named x.x.x.x_<mask> must fall inside the tenant's
allocated /21. Uses real prefix containment (not regex), so off-by-one and
cross-tenant borrowing are both caught.
"""

import ipaddress

from nac_validate import RuleBase, Violation

TENANT_ALLOCATIONS = {
    "shared-services": "198.18.192.0/21",
    "sp": "198.18.200.0/21",
    "emea-cto": "198.18.208.0/21",
    "germany": "198.18.216.0/21",
    "mea": "198.18.224.0/21",
    "north": "198.18.232.0/21",
    "south": "198.18.240.0/21",
    "uki": "198.18.248.0/21",
}


def _name_to_network(name):
    """'198.18.212.64_26' -> IPv4Network('198.18.212.64/26'), or None."""
    if not isinstance(name, str) or "_" not in name:
        return None
    base, _, mask = name.rpartition("_")
    try:
        return ipaddress.ip_network(f"{base}/{mask}", strict=False)
    except ValueError:
        return None


class Rule(RuleBase):
    id = "202"
    description = "Verify BD/EPG subnets fall within the tenant's allocated /21"
    severity = "HIGH"
    title = "Subnet outside tenant allocation"
    explanation = (
        "Each tenant owns a single /21. Bridge domains and EPGs are named after "
        "their subnet, so the name must resolve to a prefix inside that /21. "
        "Using another tenant's space causes overlapping routes and leaks."
    )
    recommendation = (
        "Choose a subnet from this tenant's allocated /21, or request a new "
        "allocation if the range is exhausted."
    )
    affected_items_label = "Out-of-range subnets"

    @classmethod
    def match(cls, data):
        violations = []
        tenants = (data.get("apic") or {}).get("tenants") or []

        for tenant in tenants:
            tname = tenant.get("name")
            allocation = TENANT_ALLOCATIONS.get(tname)
            if not allocation:
                continue  # tenant not under allocation governance (e.g. mgmt)
            allowed = ipaddress.ip_network(allocation)

            for bd in tenant.get("bridge_domains") or []:
                net = _name_to_network(bd.get("name"))
                if net is None:
                    continue  # handled by rule 401 (malformed name)
                if not net.subnet_of(allowed):
                    violations.append(
                        Violation(
                            message=(
                                f"apic.tenants[{tname}].bridge_domains"
                                f"[{bd.get('name')}] - {net} is outside the "
                                f"allocated range {allowed}"
                            ),
                            path=f"apic.tenants[{tname}].bridge_domains",
                            details=f"allocation={allowed}",
                        )
                    )

            for ap in tenant.get("application_profiles") or []:
                for epg in ap.get("endpoint_groups") or []:
                    net = _name_to_network(epg.get("name"))
                    if net is None:
                        continue
                    if not net.subnet_of(allowed):
                        violations.append(
                            Violation(
                                message=(
                                    f"apic.tenants[{tname}].application_profiles"
                                    f"[{ap.get('name')}].endpoint_groups"
                                    f"[{epg.get('name')}] - {net} is outside the "
                                    f"allocated range {allowed}"
                                ),
                                path=(
                                    f"apic.tenants[{tname}].application_profiles"
                                    f"[{ap.get('name')}].endpoint_groups"
                                ),
                            )
                        )

        return violations