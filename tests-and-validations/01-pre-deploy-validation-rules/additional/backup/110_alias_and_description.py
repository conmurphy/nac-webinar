# -*- coding: utf-8 -*-
"""
Validation Rule 405: alias and description hygiene

Bridge domains, EPGs and application profiles should carry a human-readable
alias and/or description so the intent of a subnet is discoverable without
tracing it back to the YAML. Low severity - advisory, not blocking.
"""

from nac_validate import RuleBase, Violation

# Set to True to also require 'description' (not just 'alias') on BD/EPG.
REQUIRE_DESCRIPTION = False


class Rule(RuleBase):
    id = "405"
    description = "Verify BDs, EPGs and application profiles have an alias"
    severity = "LOW"
    title = "Missing alias or description"
    explanation = (
        "Objects should be named with the subnet address and the alias should provide the human-readable intent (e.g. "
        "'prod-mysql-database')"
    )
    recommendation = (
        'Add an alias describing the segment\'s purpose, or set it to "UNUSED" '
        "if the subnet is reserved but not in service."
    )
    affected_items_label = "Undocumented objects"

    @classmethod
    def _check(cls, obj, path, kind, violations):
        if not (obj.get("alias") or "").strip():
            violations.append(
                Violation(
                    message=f"{path} - {kind} has no alias",
                    path=path,
                )
            )
        if REQUIRE_DESCRIPTION and not (obj.get("description") or "").strip():
            violations.append(
                Violation(
                    message=f"{path} - {kind} has no description",
                    path=path,
                )
            )

    @classmethod
    def match(cls, data):
        violations = []
        tenants = (data.get("apic") or {}).get("tenants") or []

        for tenant in tenants:
            tname = tenant.get("name")

            for bd in tenant.get("bridge_domains") or []:
                cls._check(
                    bd,
                    f"apic.tenants[{tname}].bridge_domains[{bd.get('name')}]",
                    "bridge domain",
                    violations,
                )

            for ap in tenant.get("application_profiles") or []:
                apname = ap.get("name")
                appath = f"apic.tenants[{tname}].application_profiles[{apname}]"
                if not (ap.get("description") or "").strip():
                    violations.append(
                        Violation(
                            message=f"{appath} - application profile has no "
                                    f"description",
                            path=appath,
                        )
                    )
                for epg in ap.get("endpoint_groups") or []:
                    cls._check(
                        epg,
                        f"{appath}.endpoint_groups[{epg.get('name')}]",
                        "EPG",
                        violations,
                    )

        return violations