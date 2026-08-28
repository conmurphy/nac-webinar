#!/usr/bin/env python3
"""
Render a terraform plan JSON as a markdown change summary.

Groups aci_rest_managed changes by action and by ACI object type, so a reviewer
can see "3 bridge domains destroyed, 3 created" instead of 100 raw resources.

Usage:  python3 plan_summary.py plan.json > plan-summary.md
"""

import json
import sys
from collections import Counter, defaultdict

# ACI class -> human readable object type
CLASS_NAMES = {
    "fvTenant": "Tenant",
    "fvCtx": "VRF",
    "fvBD": "Bridge Domain",
    "fvSubnet": "BD Subnet",
    "fvRsCtx": "BD -> VRF binding",
    "fvRsBDToOut": "BD -> L3Out binding",
    "dhcpLbl": "DHCP label",
    "dhcpRsDhcpOptionPol": "DHCP option policy binding",
    "fvAp": "Application Profile",
    "fvAEPg": "EPG",
    "fvRsBd": "EPG -> BD binding",
    "fvRsDomAtt": "EPG domain association",
    "fvRsPathAtt": "Static port binding",
    "fvESg": "Endpoint Security Group",
    "fvEPgSelector": "ESG EPG selector",
    "fvExternalSubnetSelector": "ESG subnet selector",
    "fvRsScope": "ESG -> VRF binding",
    "fvRsProv": "Contract provider",
    "fvRsCons": "Contract consumer",
    "vzBrCP": "Contract",
    "vzSubj": "Contract subject",
    "vzRsSubjFiltAtt": "Subject -> filter binding",
    "vzFilter": "Filter",
    "vzEntry": "Filter entry",
    "vzAny": "vzAny",
    "l3extOut": "L3Out",
    "l3extInstP": "External EPG",
    "l3extSubnet": "External subnet",
    "l3extLNodeP": "L3Out node profile",
    "l3extLIfP": "L3Out interface profile",
    "l3extRsNodeL3OutAtt": "L3Out node attachment",
    "l3extRsPathL3OutAtt": "L3Out path attachment",
    "l3extRsEctx": "L3Out -> VRF binding",
    "l3extRsL3DomAtt": "L3Out domain binding",
    "l3extMember": "L3Out SVI member",
    "l3extIp": "L3Out interface IP",
    "bgpExtP": "BGP enabled on L3Out",
    "bgpPeerP": "BGP peer",
    "bgpAsP": "BGP remote AS",
    "bgpLocalAsnP": "BGP local AS",
    "rtctrlSubjP": "Match rule",
    "rtctrlMatchRtDest": "Match rule prefix",
    "rtctrlProfile": "Route map",
    "rtctrlCtxP": "Route map context",
    "rtctrlRsCtxPToSubjP": "Route map -> match rule",
    "leakRoutes": "Route leak container",
    "leakInternalSubnet": "Leaked internal subnet",
    "leakExternalPrefix": "Leaked external prefix",
    "leakTo": "Leak destination",
}

ICON = {"create": "🟢", "update": "🟡", "destroy": "🔴", "replace": "🟠"}


def friendly(cls):
    return CLASS_NAMES.get(cls, cls)


def tenant_of(dn):
    if dn.startswith("uni/tn-"):
        return dn[len("uni/tn-"):].split("/", 1)[0]
    return "-"


def short_dn(dn):
    """Strip the uni/tn-<tenant>/ prefix - the tenant has its own column."""
    if dn.startswith("uni/tn-"):
        rest = dn[len("uni/tn-"):].split("/", 1)
        return rest[1] if len(rest) > 1 else "(tenant object)"
    return dn


def classify(actions):
    a = set(actions)
    if a == {"create"}:
        return "create"
    if a == {"delete"}:
        return "destroy"
    if a == {"update"}:
        return "update"
    if a == {"delete", "create"}:
        return "replace"
    return "/".join(sorted(a))


def main(path):
    with open(path) as fh:
        plan = json.load(fh)

    rows = []
    for rc in plan.get("resource_changes") or []:
        ch = rc.get("change") or {}
        actions = ch.get("actions") or []
        if not actions or set(actions) <= {"no-op", "read"}:
            continue
        after = ch.get("after") or {}
        before = ch.get("before") or {}
        cls = (after.get("class_name") or before.get("class_name")
               or rc.get("type") or "?")
        if not cls or cls == "?":
            continue
        dn = after.get("dn") or before.get("dn") or rc.get("address") or ""
        rows.append((classify(actions), cls, dn))

    if not rows:
        print("_No resource changes in this plan._")
        return

    totals = Counter(a for a, _, _ in rows)
    by_class = defaultdict(Counter)
    for act, cls, _ in rows:
        by_class[friendly(cls)][act] += 1

    order = ["create", "update", "replace", "destroy"]
    present = [a for a in order if totals.get(a)]
    present += [a for a in totals if a not in order]

    print("### Change summary")
    print()
    print("| | action | resources |")
    print("| --- | --- | --- |")
    for act in present:
        print(f"| {ICON.get(act, '⚪')} | {act} | {totals[act]} |")
    print(f"| | **total** | **{len(rows)}** |")
    print()

    print("### By object type")
    print()
    header = "| object | " + " | ".join(present) + " |"
    print(header)
    print("| --- | " + " | ".join("---" for _ in present) + " |")
    for obj in sorted(by_class, key=lambda o: -sum(by_class[o].values())):
        cells = " | ".join(str(by_class[obj].get(a, 0) or "") for a in present)
        print(f"| {obj} | {cells} |")
    print()

    for act in present:
        subset = [(c, d) for a, c, d in rows if a == act]
        if not subset:
            continue
        print(f"<details><summary>{ICON.get(act, '⚪')} "
              f"{act} ({len(subset)})</summary>")
        print()
        print("| object | tenant | dn |")
        print("| --- | --- | --- |")
        for cls, dn in sorted(subset, key=lambda x: (friendly(x[0]), x[1])):
            print(f"| {friendly(cls)} | `{tenant_of(dn)}` | `{short_dn(dn)}` |")
        print()
        print("</details>")
        print()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "plan.json")