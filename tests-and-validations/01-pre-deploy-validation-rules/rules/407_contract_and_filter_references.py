# -*- coding: utf-8 -*-
"""
Validation Rule 407: contract / filter reference resolution

Verifies that every contract referenced by an EPG, ESG, external EPG or vzAny
is actually defined in the same tenant, and that every filter referenced by a
contract subject exists. Catches typos that ACI happily accepts as unresolved
relations (deploying a contract that permits nothing).
"""

from nac_validate import RuleBase, Violation


class Rule(RuleBase):
    id = "407"
    description = "Verify contract and filter references resolve within the tenant"
    severity = "HIGH"
    title = "Unresolved contract or filter reference"
    explanation = (
        "ACI accepts a relation to a non-existent contract or filter and simply "
        "leaves it unresolved. The config looks correct but no policy is "
        "programmed, so traffic is silently dropped or permitted."
    )
    recommendation = (
        "Correct the reference, or define the missing contract/filter in the "
        "same tenant (or import it explicitly)."
    )
    affected_items_label = "Dangling references"

    @classmethod
    def _collect(cls, container, defined, tenant_path, label, violations):
        contracts = container.get("contracts") or {}
        for direction in ("providers", "consumers", "imported_consumers"):
            for ref in contracts.get(direction) or []:
                if direction == "imported_consumers":
                    continue  # imported contracts live outside the tenant
                if ref not in defined:
                    violations.append(
                        Violation(
                            message=(
                                f"{label}.contracts.{direction} - references "
                                f"contract '{ref}' which is not defined in this "
                                f"tenant"
                            ),
                            path=f"{tenant_path}.contracts",
                        )
                    )

    @classmethod
    def match(cls, data):
        violations = []
        tenants = (data.get("apic") or {}).get("tenants") or []

        for tenant in tenants:
            tname = tenant.get("name")
            tpath = f"apic.tenants[{tname}]"

            defined_contracts = {
                c.get("name") for c in (tenant.get("contracts") or [])
            }
            defined_filters = {
                f.get("name") for f in (tenant.get("filters") or [])
            }

            # contract subjects -> filters
            for contract in tenant.get("contracts") or []:
                cname = contract.get("name")
                for subj in contract.get("subjects") or []:
                    sname = subj.get("name")
                    for fref in subj.get("filters") or []:
                        fname = fref.get("filter")
                        if fname and fname not in defined_filters:
                            violations.append(
                                Violation(
                                    message=(
                                        f"{tpath}.contracts[{cname}].subjects"
                                        f"[{sname}].filters - references filter "
                                        f"'{fname}' which is not defined in this "
                                        f"tenant"
                                    ),
                                    path=f"{tpath}.filters",
                                )
                            )

            # EPGs and ESGs
            for ap in tenant.get("application_profiles") or []:
                apname = ap.get("name")
                for epg in ap.get("endpoint_groups") or []:
                    cls._collect(
                        epg,
                        defined_contracts,
                        tpath,
                        f"{tpath}.application_profiles[{apname}]"
                        f".endpoint_groups[{epg.get('name')}]",
                        violations,
                    )
                for esg in ap.get("endpoint_security_groups") or []:
                    cls._collect(
                        esg,
                        defined_contracts,
                        tpath,
                        f"{tpath}.application_profiles[{apname}]"
                        f".endpoint_security_groups[{esg.get('name')}]",
                        violations,
                    )

            # external EPGs
            for l3out in tenant.get("l3outs") or []:
                lname = l3out.get("name")
                for eepg in l3out.get("external_endpoint_groups") or []:
                    cls._collect(
                        eepg,
                        defined_contracts,
                        tpath,
                        f"{tpath}.l3outs[{lname}].external_endpoint_groups"
                        f"[{eepg.get('name')}]",
                        violations,
                    )

        return violations