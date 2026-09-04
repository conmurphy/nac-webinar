"""
Bridge domain cross-references must resolve, and every BD must be advertised.

Catches typos in BD -> VRF and BD -> L3Out references before Terraform builds a
plan against a name that was never defined, plus the ND 'bd-l3out' and
'bd-unicast' checks.

ASSUMED DATA MODEL
    apic.tenants[].name
    apic.tenants[].vrfs[].name
    apic.tenants[].l3outs[].name
    apic.tenants[].bridge_domains[].name
    apic.tenants[].bridge_domains[].vrf
    apic.tenants[].bridge_domains[].l3outs[]        (list of L3Out names)
    apic.tenants[].bridge_domains[].unicast_routing (bool, default true)
"""

REQUIRED_L3OUT = "l3out-to-core-01"


class Rule:
    id = "211"
    description = "BD references must resolve and BDs must be advertised"
    severity = "HIGH"

    @classmethod
    def match(cls, data):
        results = []
        tenants = (data.get("apic") or {}).get("tenants") or []

        for t_idx, tenant in enumerate(tenants):
            t_name = tenant.get("name", "?")
            vrf_names = {v.get("name") for v in (tenant.get("vrfs") or [])}
            l3out_names = {o.get("name") for o in (tenant.get("l3outs") or [])}

            for b_idx, bd in enumerate(tenant.get("bridge_domains") or []):
                bd_name = bd.get("name", "?")
                loc = f"apic.tenants[{t_idx}].bridge_domains[{b_idx}]"

                vrf = bd.get("vrf")
                if not vrf:
                    results.append(
                        f"{loc} - BD '{bd_name}' (tenant {t_name}) has no VRF; "
                        f"it will not route"
                    )
                elif vrf not in vrf_names:
                    results.append(
                        f"{loc} - BD '{bd_name}' references VRF '{vrf}', which "
                        f"is not defined in tenant '{t_name}'. Defined VRFs: "
                        f"{sorted(n for n in vrf_names if n)}"
                    )

                bd_l3outs = bd.get("l3outs") or []
                if REQUIRED_L3OUT not in bd_l3outs:
                    results.append(
                        f"{loc} - BD '{bd_name}' (tenant {t_name}) is not "
                        f"associated to '{REQUIRED_L3OUT}'; its subnet will not "
                        f"be advertised outside the fabric"
                    )
                for out in bd_l3outs:
                    # The required L3Out may be defined in a shared tenant, so
                    # do not demand it appear in this tenant's own list.
                    if out != REQUIRED_L3OUT and out not in l3out_names:
                        results.append(
                            f"{loc} - BD '{bd_name}' references L3Out '{out}', "
                            f"which is not defined in tenant '{t_name}'"
                        )

                # Explicit False only. An absent key means the APIC default
                # (enabled), which is what we want - do not report it.
                if bd.get("unicast_routing") is False:
                    results.append(
                        f"{loc} - BD '{bd_name}' (tenant {t_name}) has unicast "
                        f"routing disabled; its subnet will not route"
                    )

        return results