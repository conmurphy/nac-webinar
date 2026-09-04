# -*- coding: utf-8 -*-
"""
Validation Rule 116: Subnet advertisement intent vs L3Out association

Cross-checks each bridge domain's `l3outs` association against the `public`
flag on its subnets. The two have to agree, in both directions:

  public true  + l3out present -> consistent
  public true  + l3out absent  -> advertised nowhere
  public false + l3out present -> association advertises nothing
  public false + l3out absent  -> consistent, internal only

APIC accepts every one of these. In the two inconsistent cases the SVI deploys,
the anycast gateway answers inside the fabric and no fault is raised, the
subnet is simply unreachable from outside.
"""

from nac_validate import RuleBase, Violation


class Rule(RuleBase):
    id = "209"
    description = "Verify subnet public flag agrees with BD L3Out association"
    severity = "HIGH"
    title = "Subnet advertisement intent does not match L3Out association"
    explanation = (
        "A subnet with public: true is only advertised out of the fabric if its "
        "bridge domain is associated with an L3Out. Without that association the "
        "subnet deploys and the gateway answers on the fabric, but nothing "
        "external can reach it and APIC reports no fault. The reverse (an L3Out "
        "association on a bridge domain with no public subnet) advertises "
        "nothing and usually means a missing public: true."
    )
    recommendation = (
        "Either associate the bridge domain with an L3Out, or set public: false "
        "if the subnet is intentionally internal."
    )
    affected_items_label = "Inconsistent subnets"

    @classmethod
    def match(cls, data):
        violations = []
        tenants = (data.get("apic") or {}).get("tenants") or []

        for tenant in tenants:
            tname = tenant.get("name")

            # L3Outs defined in this tenant. A BD can only usefully reference one
            # of these, so a name that is not here advertises nothing even though
            # the association exists.
            tenant_l3outs = {
                lo.get("name")
                for lo in tenant.get("l3outs") or []
                if lo.get("name")
            }

            for bd in tenant.get("bridge_domains") or []:
                bname = bd.get("name")
                bd_path = f"apic.tenants[{tname}].bridge_domains[{bname}]"

                # A BD with no VRF cannot route at all, so the public flag is not
                # yet meaningful. Left to whichever rule asserts VRF presence.
                if not bd.get("vrf"):
                    continue

                l3outs = [x for x in (bd.get("l3outs") or []) if x]
                subnets = bd.get("subnets") or []

                # An L3Out name that does not resolve produces an unresolved
                # relation on the fabric: Terraform succeeds, APIC raises a fault,
                # and the subnet is advertised nowhere. Treat it as absent so the
                # public-with-no-l3out check below still fires.
                unresolved = [lo for lo in l3outs if lo not in tenant_l3outs]
                resolved = [lo for lo in l3outs if lo in tenant_l3outs]

                for lo in unresolved:
                    violations.append(
                        Violation(
                            message=(
                                f"{bd_path}.l3outs - '{lo}' is not defined in "
                                f"tenant '{tname}', so the association resolves "
                                f"to nothing and cannot advertise any subnet"
                            ),
                            path=bd_path,
                            details=(
                                f"known l3outs in this tenant: "
                                f"{sorted(tenant_l3outs) or 'none'}"
                            ),
                        )
                    )

                has_l3out = bool(resolved)
                l3out_label = ", ".join(resolved) if resolved else "none"

                # ── direction 1: public subnet with nothing to advertise it ──
                # Evaluated per subnet, because the flag is per subnet.
                public_count = 0
                shared_count = 0

                for idx, subnet in enumerate(subnets):
                    sip = subnet.get("ip")
                    if not sip:
                        continue

                    is_public = bool(subnet.get("public", False))
                    is_shared = bool(subnet.get("shared", False))

                    if is_public:
                        public_count += 1
                    if is_shared:
                        shared_count += 1

                    if is_public and not has_l3out:
                        violations.append(
                            Violation(
                                message=(
                                    f"{bd_path}.subnets[{idx}] - {sip} is "
                                    f"public: true but bridge domain "
                                    f"'{bname}' has no resolvable L3Out "
                                    f"association, so nothing advertises this "
                                    f"subnet out of the fabric"
                                ),
                                path=f"{bd_path}.subnets[{idx}]",
                                details=(
                                    "add the BD to an l3out, or set "
                                    "public: false if it is internal"
                                ),
                            )
                        )

                # ── direction 2: L3Out association that advertises nothing ──
                # Evaluated per BD, NOT per subnet. A BD may legitimately mix a
                # public subnet with a private one; only a BD where NO subnet is
                # public makes the association inert.
                if has_l3out and subnets and public_count == 0:
                    detail = (
                        f"{len(subnets)} subnet(s), none public"
                    )
                    if shared_count:
                        detail += (
                            f"; {shared_count} marked shared, which leaks "
                            f"between VRFs and does not require an L3Out"
                        )
                    violations.append(
                        Violation(
                            message=(
                                f"{bd_path} - associated with L3Out "
                                f"{l3out_label} but no subnet is public: true, "
                                f"so the association advertises nothing"
                            ),
                            path=bd_path,
                            details=detail,
                        )
                    )

        return violations