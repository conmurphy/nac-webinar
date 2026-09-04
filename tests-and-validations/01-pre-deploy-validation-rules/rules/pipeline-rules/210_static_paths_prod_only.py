"""
EPGs may only bind static paths to permitted UCS domains.

Replaces the ND 'static-prod-only' compliance rule, which cannot do this job at
plan time: ND pre-change analysis strips fvRsPathAtt from newly created objects,
so a test/sandbox binding on a brand-new EPG is invisible to it. Reading the
declared intent has no such blind spot - the violation is caught before commit.

ASSUMED DATA MODEL
    apic.tenants[].application_profiles[].endpoint_groups[].name
    apic.tenants[].application_profiles[].endpoint_groups[].static_ports[]
        .channel   (vPC / port-channel name)  -- or .port for access ports

MAINTENANCE
    UCS_DOMAIN_PATHS is duplicated in 06_static_port_domain_coverage.py.
    grep for 'DUPLICATED-IN' to find every copy before editing.
"""

# DUPLICATED-IN: 06_static_port_domain_coverage.py
UCS_DOMAIN_PATHS = {
    "prod": [
        "vpc-ucs-prod-01-6454-A",
        "vpc-ucs-prod-01-6454-B",
    ],
    "test": [
        "vpc-ucs-test-01-6536-A",
        "vpc-ucs-test-01-6536-B",
    ],
    "sandbox": [
        "vpc-ucs-sandbox-01-6454-A",
        "vpc-ucs-sandbox-01-6454-B",
    ],
}

# Domains an EPG is permitted to bind to. Prod-only: dev and sandbox must not
# share a segment with prod.
ALLOWED_DOMAINS = {"prod"}


class Rule:
    id = "210"
    description = "EPG static paths must only use permitted UCS domains"
    severity = "HIGH"

    @staticmethod
    def _path_name(entry):
        # Tolerate either key: vPC/PC bindings use 'channel', access ports 'port'.
        for key in ("channel", "port", "path", "name"):
            value = entry.get(key)
            if value:
                return str(value)
        return ""

    @classmethod
    def match(cls, data):
        results = []
        domain_of = {p: dom
                     for dom, paths in UCS_DOMAIN_PATHS.items()
                     for p in paths}
        forbidden = sorted(set(UCS_DOMAIN_PATHS) - ALLOWED_DOMAINS)
        tenants = (data.get("apic") or {}).get("tenants") or []

        for t_idx, tenant in enumerate(tenants):
            t_name = tenant.get("name", "?")

            for a_idx, ap in enumerate(tenant.get("application_profiles") or []):
                for e_idx, epg in enumerate(ap.get("endpoint_groups") or []):
                    epg_name = epg.get("name", "?")

                    for p_idx, entry in enumerate(epg.get("static_ports") or []):
                        path = cls._path_name(entry)
                        if not path:
                            continue

                        loc = (f"apic.tenants[{t_idx}].application_profiles"
                               f"[{a_idx}].endpoint_groups[{e_idx}]"
                               f".static_ports[{p_idx}]")
                        dom = domain_of.get(path)

                        if dom is None:
                            # Unknown path: cannot prove it is safe, so report.
                            # A silent pass here is how a segmentation breach
                            # slips through on a renamed bundle.
                            results.append(
                                f"{loc} - EPG '{epg_name}' (tenant {t_name}) "
                                f"binds to unrecognised path '{path}'. Add it "
                                f"to UCS_DOMAIN_PATHS or correct the name."
                            )
                        elif dom not in ALLOWED_DOMAINS:
                            results.append(
                                f"{loc} - SEGMENTATION BREACH: EPG "
                                f"'{epg_name}' (tenant {t_name}) binds to "
                                f"'{path}' in the {dom} UCS domain. Only "
                                f"{sorted(ALLOWED_DOMAINS)} permitted - "
                                f"{'/'.join(forbidden)} must not reach prod "
                                f"segments."
                            )

        return results