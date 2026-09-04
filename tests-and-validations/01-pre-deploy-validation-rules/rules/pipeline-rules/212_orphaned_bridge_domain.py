"""
Every bridge domain must be referenced by at least one EPG.

Reverse-reference analysis: requires the whole data model at once, so there is
no per-object ND compliance equivalent. An orphaned BD burns a subnet from the
tenant allocation and quietly accumulates - usually the residue of a
half-completed decommission.

Advisory rather than blocking: a BD may legitimately be staged ahead of its EPG.
Raise the severity if your workflow does not allow that.

ASSUMED DATA MODEL
    apic.tenants[].name
    apic.tenants[].bridge_domains[].name
    apic.tenants[].application_profiles[].endpoint_groups[].bridge_domain
"""


class Rule:
    id = "212"
    description = "Bridge domains should be referenced by an EPG"
    severity = "MEDIUM"

    @classmethod
    def match(cls, data):
        results = []
        tenants = (data.get("apic") or {}).get("tenants") or []

        for t_idx, tenant in enumerate(tenants):
            t_name = tenant.get("name", "?")

            defined = {}
            for b_idx, bd in enumerate(tenant.get("bridge_domains") or []):
                name = bd.get("name")
                if name:
                    defined[name] = b_idx

            referenced = set()
            for ap in tenant.get("application_profiles") or []:
                for epg in ap.get("endpoint_groups") or []:
                    bd_ref = epg.get("bridge_domain")
                    if bd_ref:
                        referenced.add(bd_ref)

            for name in sorted(set(defined) - referenced):
                results.append(
                    f"apic.tenants[{t_idx}].bridge_domains[{defined[name]}] - "
                    f"BD '{name}' (tenant {t_name}) is not referenced by any "
                    f"EPG. Its subnet is allocated but unreachable - remove it "
                    f"or add the EPG."
                )

            # The inverse is a hard error and worth catching here while both
            # sets are in hand.
            for a_idx, ap in enumerate(tenant.get("application_profiles") or []):
                for e_idx, epg in enumerate(ap.get("endpoint_groups") or []):
                    bd_ref = epg.get("bridge_domain")
                    if bd_ref and bd_ref not in defined:
                        results.append(
                            f"apic.tenants[{t_idx}].application_profiles"
                            f"[{a_idx}].endpoint_groups[{e_idx}] - EPG "
                            f"'{epg.get('name','?')}' references BD '{bd_ref}', "
                            f"which is not defined in tenant '{t_name}'"
                        )

        return results