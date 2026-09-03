# -*- coding: utf-8 -*-
"""
Validation Rule 410: ESG epg_selector resolution and coverage

Endpoint Security Groups select EPGs by name via epg_selectors[]. ACI accepts a
selector pointing at a non-existent EPG and simply leaves it unresolved, so the
EPG silently never joins the security group. With an enforced VRF that means the
segment gets no contracts at all and its traffic is dropped - with no error
raised anywhere in APIC.

Checks performed:
  1. Each selector's application_profile exists in the tenant.
  2. Each selector's endpoint_group exists in that application profile.
  3. No EPG is selected twice within the same ESG (redundant selector).
  4. No EPG is selected by more than one ESG (an EPG belongs to one ESG only).
  5. The ESG's VRF matches the VRF of the selected EPG's bridge domain.
  6. Coverage: in tenants listed in ESG_COVERAGE_TENANTS, every EPG must be
     selected by some ESG (otherwise it receives no policy).
"""

from nac_validate import RuleBase, Violation

# The tenants we want to check
ESG_COVERAGE_TENANTS = {"emea-cto"}

# EPGs intentionally left out of any ESG: (tenant, application_profile, epg).
COVERAGE_EXEMPTIONS = set()

# Set False if your ACI version permits an EPG in multiple ESGs.
ENFORCE_SINGLE_ESG_MEMBERSHIP = True


class Rule(RuleBase):
    id = "410"
    description = (
        "Verify ESG epg_selectors resolve and cover every EPG"
    )
    severity = "HIGH"
    title = "ESG selector unresolved or EPG uncovered"
    explanation = (
        "All EPGs should belong to an ESG"
    )
    recommendation = (
        "Correct the selector to name an existing application_profile and "
        "endpoint_group, or add the missing EPG to the appropriate ESG. Record "
        "deliberate omissions in COVERAGE_EXEMPTIONS."
    )
    affected_items_label = "Selector problems"

    @classmethod
    def _index_epgs(cls, tenant):
        """{app_profile_name: {epg_name: bd_name}} incl. uSeg EPGs."""
        index = {}
        for ap in tenant.get("application_profiles") or []:
            apname = ap.get("name")
            epgs = {}
            for key in ("endpoint_groups", "useg_endpoint_groups"):
                for epg in ap.get(key) or []:
                    epgs[epg.get("name")] = epg.get("bridge_domain")
            index[apname] = epgs
        return index

    @classmethod
    def _index_bd_vrfs(cls, tenant):
        """{bd_name: vrf_name}"""
        return {
            bd.get("name"): bd.get("vrf")
            for bd in tenant.get("bridge_domains") or []
        }

    @classmethod
    def match(cls, data):
        violations = []
        tenants = (data.get("apic") or {}).get("tenants") or []

        for tenant in tenants:
            tname = tenant.get("name")
            tpath = f"apic.tenants[{tname}]"
            epg_index = cls._index_epgs(tenant)
            bd_vrfs = cls._index_bd_vrfs(tenant)

            # (ap, epg) -> [esg names that select it]
            selected_by = {}

            for ap in tenant.get("application_profiles") or []:
                host_ap = ap.get("name")
                for esg in ap.get("endpoint_security_groups") or []:
                    esg_name = esg.get("name")
                    esg_vrf = esg.get("vrf")
                    epath = (
                        f"{tpath}.application_profiles[{host_ap}]"
                        f".endpoint_security_groups[{esg_name}]"
                    )
                    seen_in_this_esg = set()

                    for sel in esg.get("epg_selectors") or []:
                        # selector may omit application_profile -> its own AP
                        sel_ap = sel.get("application_profile") or host_ap
                        sel_epg = sel.get("endpoint_group")
                        spath = f"{epath}.epg_selectors"

                        if not sel_epg:
                            violations.append(
                                Violation(
                                    message=(
                                        f"{spath} - selector has no "
                                        f"endpoint_group specified"
                                    ),
                                    path=spath,
                                )
                            )
                            continue

                        # 1. application profile must exist
                        if sel_ap not in epg_index:
                            violations.append(
                                Violation(
                                    message=(
                                        f"{spath} - references application "
                                        f"profile '{sel_ap}' which is not "
                                        f"defined in tenant '{tname}'"
                                    ),
                                    path=spath,
                                    details=(
                                        "defined profiles: "
                                        f"{sorted(epg_index)}"
                                    ),
                                )
                            )
                            continue

                        # 2. EPG must exist in that application profile
                        if sel_epg not in epg_index[sel_ap]:
                            violations.append(
                                Violation(
                                    message=(
                                        f"{spath} - references EPG '{sel_epg}' "
                                        f"which is not defined in application "
                                        f"profile '{sel_ap}'"
                                    ),
                                    path=spath,
                                    details=(
                                        "the selector will be unresolved and "
                                        "the EPG will receive no policy"
                                    ),
                                )
                            )
                            continue

                        # 3. duplicate selector inside the same ESG
                        key = (sel_ap, sel_epg)
                        if key in seen_in_this_esg:
                            violations.append(
                                Violation(
                                    message=(
                                        f"{spath} - EPG '{sel_epg}' is selected "
                                        f"more than once by ESG '{esg_name}'"
                                    ),
                                    path=spath,
                                )
                            )
                        seen_in_this_esg.add(key)
                        selected_by.setdefault(key, []).append(esg_name)

                        # 5. ESG VRF must match the selected EPG's BD VRF
                        bd_name = epg_index[sel_ap].get(sel_epg)
                        bd_vrf = bd_vrfs.get(bd_name)
                        if esg_vrf and bd_vrf and esg_vrf != bd_vrf:
                            violations.append(
                                Violation(
                                    message=(
                                        f"{spath} - ESG '{esg_name}' is in VRF "
                                        f"'{esg_vrf}' but selected EPG "
                                        f"'{sel_epg}' has BD '{bd_name}' in VRF "
                                        f"'{bd_vrf}'"
                                    ),
                                    path=spath,
                                    details=(
                                        "an ESG can only select EPGs whose "
                                        "bridge domain is in the same VRF"
                                    ),
                                )
                            )

            # 4. an EPG must not be selected by multiple ESGs
            if ENFORCE_SINGLE_ESG_MEMBERSHIP:
                for (sel_ap, sel_epg), esgs in sorted(selected_by.items()):
                    distinct = sorted(set(esgs))
                    if len(distinct) > 1:
                        violations.append(
                            Violation(
                                message=(
                                    f"{tpath}.application_profiles[{sel_ap}]"
                                    f".endpoint_groups[{sel_epg}] - selected by "
                                    f"multiple ESGs: {', '.join(distinct)}"
                                ),
                                path=f"{tpath}.application_profiles",
                                details=(
                                    "an EPG can be a member of only one ESG"
                                ),
                            )
                        )

            # 6. coverage: every EPG must belong to an ESG
            if tname in ESG_COVERAGE_TENANTS:
                covered = set(selected_by)
                for sel_ap, epgs in sorted(epg_index.items()):
                    for epg_name in sorted(epgs):
                        if (sel_ap, epg_name) in covered:
                            continue
                        if (tname, sel_ap, epg_name) in COVERAGE_EXEMPTIONS:
                            continue
                        violations.append(
                            Violation(
                                message=(
                                    f"{tpath}.application_profiles[{sel_ap}]"
                                    f".endpoint_groups[{epg_name}] - not "
                                    f"selected by any ESG; with an enforced VRF "
                                    f"this EPG receives no contracts and its "
                                    f"traffic will be dropped"
                                ),
                                path=f"{tpath}.application_profiles[{sel_ap}]",
                                details=(
                                    "add an epg_selector to the appropriate ESG"
                                ),
                            )
                        )

        return violations