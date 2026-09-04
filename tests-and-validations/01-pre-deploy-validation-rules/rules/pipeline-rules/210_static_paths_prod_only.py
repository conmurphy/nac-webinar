"""
EPGs may only bind static paths to permitted UCS domains.

MAINTENANCE
    UCS_DOMAIN_PATHS is duplicated in 204_static_port_domain_coverage.py.
    grep for 'DUPLICATED-IN' to find every copy before editing.
"""

from nac_validate import RuleBase, Violation

# DUPLICATED-IN: 204_static_port_domain_coverage.py
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

# Domains an EPG is permitted to bind to. Prod-only: dev and sandbox workloads
# must not share a segment with production.
#
# MUST be a superset of REQUIRED_DOMAINS in 204_static_port_domain_coverage.py.
# If 204 requires a domain this rule forbids, no configuration can satisfy both.
ALLOWED_DOMAINS = {"prod"}


class Rule(RuleBase):
    id = "210"
    description = "EPG static paths must only use permitted UCS domains"
    severity = "HIGH"

    title = "EPGs with forbidden static paths"
    affected_items_label = "EPGs with forbidden static paths"

    explanation = """\
A static path binding places the EPG's VLAN on that leaf interface. Adding a
test or sandbox UCS path to a production segment puts non-production workloads
in the same bridge domain and the same EPG as production hosts.
"""

    recommendation = """\
Remove the non-prod static_ports entries from the EPG. A production segment
should carry only the prod UCS domain, on both vPC legs:

  application_profiles:
    - name: network-segments
      endpoint_groups:
        - name: 198.18.215.128_26
          static_ports:
            - channel: vpc-ucs-prod-01-6454-A
            - channel: vpc-ucs-prod-01-6454-B
            # test and sandbox paths are not permitted on prod segments

If a workload genuinely needs to live on the test or sandbox compute pool, give
it its own EPG and bridge domain, and connect the two with an explicit contract
so the traffic is visible and controllable."""

    @staticmethod
    def _path_name(entry):
        # Tolerate either key: vPC and port-channel bindings use 'channel',
        # access ports use 'port'.
        for key in ("channel", "port", "path", "name"):
            value = entry.get(key)
            if value:
                return str(value)
        return ""

    @classmethod
    def match(cls, data):
        violations = []
        domain_of = {p: dom
                     for dom, paths in UCS_DOMAIN_PATHS.items()
                     for p in paths}
        forbidden = sorted(set(UCS_DOMAIN_PATHS) - ALLOWED_DOMAINS)
        tenants = (data.get("apic") or {}).get("tenants") or []

        for tenant in tenants:
            t_name = tenant.get("name", "?")

            for ap in tenant.get("application_profiles") or []:
                ap_name = ap.get("name", "?")

                for epg in ap.get("endpoint_groups") or []:
                    epg_name = epg.get("name", "?")

                    for entry in epg.get("static_ports") or []:
                        path_name = cls._path_name(entry)
                        if not path_name:
                            continue

                        base = (f"apic.tenants[name={t_name}]"
                                f".application_profiles[name={ap_name}]"
                                f".endpoint_groups[name={epg_name}]"
                                f".static_ports[{path_name}]")
                        dom = domain_of.get(path_name)

                        if dom is None:
                            # An unrecognised path cannot be proven safe. A
                            # silent pass here is how a breach slips through on
                            # a renamed bundle.
                            violations.append(Violation(
                                message=(f"EPG '{epg_name}' binds to "
                                         f"unrecognised path '{path_name}'; it "
                                         f"cannot be verified against the "
                                         f"permitted UCS domains"),
                                path=base,
                                details={
                                    "tenant": t_name,
                                    "epg": epg_name,
                                    "path": path_name,
                                    "domain": None,
                                    "allowed_domains": sorted(ALLOWED_DOMAINS),
                                },
                            ))
                        elif dom not in ALLOWED_DOMAINS:
                            violations.append(Violation(
                                message=(f"EPG '{epg_name}' binds to "
                                         f"'{path_name}' in the {dom} UCS "
                                         f"domain. Only "
                                         f"{sorted(ALLOWED_DOMAINS)} is "
                                         f"permitted - "
                                         f"{'/'.join(forbidden)} workloads "
                                         f"must not share a segment with "
                                         f"production"),
                                path=base,
                                details={
                                    "tenant": t_name,
                                    "epg": epg_name,
                                    "path": path_name,
                                    "domain": dom,
                                    "allowed_domains": sorted(ALLOWED_DOMAINS),
                                },
                            ))

        return violations