# -*- coding: utf-8 -*-
"""
Validation Rule 402: BD <-> EPG pairing

In this design every network segment is a BD plus an identically-named EPG that
references it. Verifies:
  1. Every EPG's bridge_domain reference resolves to a BD in the same tenant.
  2. EPG name == referenced BD name (naming convention).
  3. Every BD has at least one EPG referencing it (no orphan BDs).

ESG-only / leaked subnets have no BD by design and are excluded via
ESG_ONLY_TENANT_PREFIXES handling in rule 404 instead.
"""

from nac_validate import RuleBase, Violation

# BDs in these tenants that are intentionally EPG-less (e.g. service BDs).
# Add exact BD names to suppress the "orphan BD" check.
ORPHAN_BD_ALLOWLIST = {
    ("shared-services", "198.18.193.240_28"),  # firewall service BD, no EPG
}


class Rule(RuleBase):
    id = "203"
    description = "Verify every EPG resolves to a BD and every BD has an EPG"
    severity = "HIGH"
    title = "BD / EPG pairing broken"
    explanation = (
        "Each network segment is a BD plus a same-named EPG. A dangling EPG->BD "
        "reference deploys an EPG with no gateway; an orphan BD consumes a "
        "subnet and VLAN with nothing attached to it."
    )
    recommendation = (
        "Add the missing BD or EPG, or correct the bridge_domain reference. "
        "If a BD is intentionally EPG-less, add it to ORPHAN_BD_ALLOWLIST."
    )
    affected_items_label = "Unpaired objects"

    @classmethod
    def match(cls, data):
        violations = []
        tenants = (data.get("apic") or {}).get("tenants") or []

        for tenant in tenants:
            tname = tenant.get("name")
            bd_names = {
                bd.get("name") for bd in (tenant.get("bridge_domains") or [])
            }
            referenced_bds = set()

            for ap in tenant.get("application_profiles") or []:
                apname = ap.get("name")
                for epg in ap.get("endpoint_groups") or []:
                    epg_name = epg.get("name")
                    bd_ref = epg.get("bridge_domain")
                    path = (
                        f"apic.tenants[{tname}].application_profiles[{apname}]"
                        f".endpoint_groups[{epg_name}]"
                    )

                    if not bd_ref:
                        violations.append(
                            Violation(
                                message=f"{path} - EPG has no bridge_domain "
                                        f"reference",
                                path=path,
                            )
                        )
                        continue

                    referenced_bds.add(bd_ref)

                    # 1. reference must resolve
                    if bd_ref not in bd_names:
                        violations.append(
                            Violation(
                                message=(
                                    f"{path}.bridge_domain - references "
                                    f"'{bd_ref}' which is not defined in tenant "
                                    f"'{tname}'"
                                ),
                                path=f"{path}.bridge_domain",
                            )
                        )
                        continue

                    # 2. names must match
                    if epg_name != bd_ref:
                        violations.append(
                            Violation(
                                message=(
                                    f"{path} - EPG name does not match its BD "
                                    f"'{bd_ref}' (convention: EPG name == BD name)"
                                ),
                                path=path,
                                details=f"expected EPG name '{bd_ref}'",
                            )
                        )

            # 3. orphan BDs
            for bd_name in sorted(bd_names - referenced_bds):
                if (tname, bd_name) in ORPHAN_BD_ALLOWLIST:
                    continue
                violations.append(
                    Violation(
                        message=(
                            f"apic.tenants[{tname}].bridge_domains[{bd_name}] - "
                            f"no EPG references this BD"
                        ),
                        path=f"apic.tenants[{tname}].bridge_domains",
                    )
                )

        return violations