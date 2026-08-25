# -*- coding: utf-8 -*-
"""
Validation Rule 406: VLAN uniqueness per tenant

Flags VLANs outside the configured allowed range for the tenant.
"""

from collections import defaultdict

from nac_validate import RuleBase, Violation

# Optional per-tenant allowed VLAN ranges (inclusive). Omit a tenant to skip.
TENANT_VLAN_RANGES = {
    "sp": (1100, 1199),
    "emea-cto": (1200, 1299),
    "germany": (1300, 1399),
    "mea": (1400, 1499),
    "north": (1500, 1599),
    "south": (1600, 1699),
    "uki": (1700, 1799),
}


class Rule(RuleBase):
    id = "406"
    description = "Verify encap VLANs are unique per tenant and within range"
    severity = "HIGH"
    title = "VLAN conflict or out of range"
    explanation = (
        "Allocate a unique VLAN per segment from the tenant's assigned range."
    )
    recommendation = (
        "Allocate a unique VLAN per segment from the tenant's assigned range."
    )
    affected_items_label = "Conflicting VLANs"

    @classmethod
    def match(cls, data):
        violations = []
        tenants = (data.get("apic") or {}).get("tenants") or []

        for tenant in tenants:
            tname = tenant.get("name")
            # (vlan, channel) -> [epg names]
            usage = defaultdict(list)
            vlan_range = TENANT_VLAN_RANGES.get(tname)

            for ap in tenant.get("application_profiles") or []:
                apname = ap.get("name")
                for epg in ap.get("endpoint_groups") or []:
                    epg_name = epg.get("name")
                    path = (
                        f"apic.tenants[{tname}].application_profiles[{apname}]"
                        f".endpoint_groups[{epg_name}]"
                    )
                    reported_vlans = set()          # <-- add
                    for sp in epg.get("static_ports") or []:
                        vlan = sp.get("vlan")
                        channel = sp.get("channel")
                        if vlan is None:
                            continue
                        usage[(vlan, channel)].append(epg_name)

                        if (
                            vlan_range
                            and vlan not in reported_vlans          # <-- add
                            and not (vlan_range[0] <= int(vlan) <= vlan_range[1])
                        ):
                            reported_vlans.add(vlan)                # <-- add
                            violations.append(
                                Violation(
                                    message=(
                                        f"{path}.static_ports - VLAN {vlan} is "
                                        f"outside the range allocated to "
                                        f"'{tname}' "
                                        f"({vlan_range[0]}-{vlan_range[1]})"
                                    ),
                                    path=f"{path}.static_ports",
                                )
                            )

            for (vlan, channel), epgs in sorted(usage.items()):
                distinct = sorted(set(epgs))
                if len(distinct) > 1:
                    violations.append(
                        Violation(
                            message=(
                                f"apic.tenants[{tname}] - VLAN {vlan} on channel "
                                f"'{channel}' is used by multiple EPGs: "
                                f"{', '.join(distinct)}"
                            ),
                            path=f"apic.tenants[{tname}].application_profiles",
                            details=f"vlan={vlan} channel={channel}",
                        )
                    )

        return violations