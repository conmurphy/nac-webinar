# -*- coding: utf-8 -*-
"""
Validation Rule 404: shared-services subnet replication

Adding a subnet to shared-services requires touching several sections that must
stay in lock-step. This rule set-compares them:

  A. policies.match_rules[]                     name + prefix
  B. l3outs[export].export_route_map.contexts[] name + match_rules ref
  C. vrfs[].leaked_internal_prefixes[] /
     vrfs[].leaked_external_prefixes[]          prefix
  D. application_profiles[].endpoint_security_groups[]
       .ip_external_subnet_selectors[]          prefix (ESG/leaked class)

Checks performed:
  1. Every route-map context references a match_rule that EXISTS.
  2. Every match_rule is referenced by a route-map context (no orphans).
  3. Every match_rule's prefix agrees with its own name.
  4. Every leaked prefix has a match_rule AND a route-map context.
  5. Every ESG external-subnet selector has a matching leak entry.

This is a cross-section set comparison and cannot be expressed as an ND
template - it is the primary reason this rule lives pre-commit.
"""

import ipaddress

from nac_validate import RuleBase, Violation

TARGET_TENANT = "shared-services"
EXPORT_L3OUT = "l3out-to-core-01"
EXPORT_ROUTE_MAP = "default-export"

# Catch-all / architectural prefixes that intentionally do NOT participate in
# the per-subnet replication pattern:
#   0.0.0.0/0            default route leaked vrf-external -> vrf-internal
#   0.0.0.0/1 + 128.0.0.0/1  'external-subnets' ESG catch-all classifiers
PREFIX_IGNORE = {
    "0.0.0.0/0",
    "0.0.0.0/1",
    "128.0.0.0/1",
}


def _name_to_prefix(name):
    """'198.18.194.192_27' -> '198.18.194.192/27' normalised, else None."""
    if not isinstance(name, str) or "_" not in name:
        return None
    base, _, mask = name.rpartition("_")
    try:
        return str(ipaddress.ip_network(base + "/" + mask, strict=False))
    except ValueError:
        return None


def _norm(prefix):
    """Normalise a CIDR string, else None."""
    try:
        return str(ipaddress.ip_network(prefix, strict=False))
    except (ValueError, TypeError):
        return None


class Rule(RuleBase):
    id = "404"
    description = (
        "Verify shared-services subnets are replicated across match rules, "
        "route-map contexts, VRF leaks and ESG selectors"
    )
    severity = "HIGH"
    title = "Incomplete subnet replication"
    explanation = (
        "A shared-services subnet must appear in every section that makes it "
        "reachable: a match rule, an export route-map context that references "
        "that rule, a VRF leak entry, and (for leaked/ESG subnets) an ESG "
        "external-subnet selector. Missing any one leaves the route silently "
        "un-advertised or un-leaked while the config still looks complete."
    )
    recommendation = (
        "Add the missing section for the subnet. Every subnet should appear in "
        "match_rules, export_route_map.contexts, the VRF leak list, and the ESG "
        "selector where applicable."
    )
    affected_items_label = "Replication gaps"

    @classmethod
    def match(cls, data):
        violations = []
        tenants = (data.get("apic") or {}).get("tenants") or []
        tenant = None
        for t in tenants:
            if t.get("name") == TARGET_TENANT:
                tenant = t
                break
        if tenant is None:
            return violations

        base = "apic.tenants[" + TARGET_TENANT + "]"

        # ---- A. match rules -------------------------------------------------
        match_rules = {}
        for mr in (tenant.get("policies") or {}).get("match_rules") or []:
            name = mr.get("name")
            prefixes = []
            for p in mr.get("prefixes") or []:
                norm = _norm(p.get("ip"))
                if norm:
                    prefixes.append(norm)
            match_rules[name] = prefixes

        # ---- B. export route-map contexts -----------------------------------
        ctx_refs = {}
        for l3out in tenant.get("l3outs") or []:
            if l3out.get("name") != EXPORT_L3OUT:
                continue
            rm = l3out.get("export_route_map") or {}
            if rm.get("name") != EXPORT_ROUTE_MAP:
                continue
            for ctx in rm.get("contexts") or []:
                ctx_refs[ctx.get("name")] = list(ctx.get("match_rules") or [])

        # ---- C. VRF leaks ---------------------------------------------------
        leaked = set()
        for vrf in tenant.get("vrfs") or []:
            for key in ("leaked_internal_prefixes", "leaked_external_prefixes"):
                for entry in vrf.get(key) or []:
                    norm = _norm(entry.get("prefix"))
                    if norm and norm not in PREFIX_IGNORE:
                        leaked.add(norm)

        # ---- D. ESG external subnet selectors -------------------------------
        esg_selectors = {}
        for ap in tenant.get("application_profiles") or []:
            for esg in ap.get("endpoint_security_groups") or []:
                for sel in esg.get("ip_external_subnet_selectors") or []:
                    norm = _norm(sel.get("ip"))
                    if norm and norm not in PREFIX_IGNORE:
                        esg_selectors[norm] = esg.get("name")

        rm_path = base + ".policies.match_rules"
        ctx_path = (base + ".l3outs[" + EXPORT_L3OUT
                    + "].export_route_map.contexts")

        # ==== 1. dangling context -> match_rule references ===================
        for cname in sorted(ctx_refs):
            refs = ctx_refs[cname]
            if not refs:
                violations.append(
                    Violation(
                        message=(
                            ctx_path + "[" + str(cname) + "] - context has no "
                            "match_rules reference; nothing will be advertised"
                        ),
                        path=ctx_path,
                    )
                )
            for ref in refs:
                if ref not in match_rules:
                    violations.append(
                        Violation(
                            message=(
                                ctx_path + "[" + str(cname) + "].match_rules - "
                                "references match_rule '" + str(ref) + "' which "
                                "is NOT defined in policies.match_rules"
                            ),
                            path=rm_path,
                            details="add the match_rule, or fix the reference",
                        )
                    )

        # ==== 2. orphan match rules ==========================================
        all_refs = set()
        for refs in ctx_refs.values():
            all_refs.update(refs)
        for name in sorted(set(match_rules) - all_refs):
            violations.append(
                Violation(
                    message=(
                        rm_path + "[" + str(name) + "] - defined but not "
                        "referenced by any '" + EXPORT_ROUTE_MAP + "' context "
                        "(did you forget the route-map context?)"
                    ),
                    path=ctx_path,
                )
            )

        # ==== 3. match rule name vs its own prefix ===========================
        for name in sorted(match_rules):
            prefixes = match_rules[name]
            expected = _name_to_prefix(name)
            if expected is None:
                violations.append(
                    Violation(
                        message=(
                            rm_path + "[" + str(name) + "] - name does not "
                            "follow the x.x.x.x_<mask> convention"
                        ),
                        path=rm_path,
                    )
                )
                continue
            if expected not in prefixes:
                violations.append(
                    Violation(
                        message=(
                            rm_path + "[" + str(name) + "] - name implies "
                            + expected + " but prefixes are "
                            + (str(prefixes) if prefixes else "[]")
                        ),
                        path=rm_path,
                        details="expected prefix " + expected,
                    )
                )

        # ==== 4. every leaked prefix has a match rule + context ==============
        mr_prefixes = set()
        for prefixes in match_rules.values():
            mr_prefixes.update(prefixes)

        ctx_prefixes = set()
        for cname in ctx_refs:
            norm = _name_to_prefix(cname)
            if norm:
                ctx_prefixes.add(norm)

        for prefix in sorted(leaked):
            if prefix not in mr_prefixes:
                violations.append(
                    Violation(
                        message=(
                            base + ".vrfs[*].leaked_*_prefixes - " + prefix
                            + " is leaked but has no match_rule; it will not be "
                            "advertised out " + EXPORT_L3OUT
                        ),
                        path=rm_path,
                    )
                )
            if prefix not in ctx_prefixes:
                violations.append(
                    Violation(
                        message=(
                            base + ".vrfs[*].leaked_*_prefixes - " + prefix
                            + " is leaked but has no '" + EXPORT_ROUTE_MAP
                            + "' context"
                        ),
                        path=ctx_path,
                    )
                )

        # ==== 5. every ESG selector has a leak entry =========================
        for prefix in sorted(esg_selectors):
            if prefix not in leaked:
                violations.append(
                    Violation(
                        message=(
                            base + ".application_profiles[*]"
                            ".endpoint_security_groups["
                            + str(esg_selectors[prefix])
                            + "].ip_external_subnet_selectors - " + prefix
                            + " is selected by an ESG but has no VRF leak entry"
                        ),
                        path=base + ".vrfs",
                        details="add to leaked_external_prefixes",
                    )
                )

        return violations