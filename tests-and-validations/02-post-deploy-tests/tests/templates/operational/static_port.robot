{# iterate_list apic.tenants name item[2] #}
*** Settings ***
Documentation     Verify EPG Static Path Deployment
...
...               Two assertion levels per path:
...                 1. The fvRsPathAtt MO exists (config accepted by APIC).
...                 2. Its relation is not 'missing-target', which would mean the
...                    vPC or interface policy group named in the path does not
...                    exist - config present, no connectivity.
...
...               NOTE: state='formed' is NOT asserted. Verified on this fabric
...               that working vPC static paths report state='unformed' while
...               vlanCktEp shows operSt=up with a real hwId, because the target
...               fabricPathEp lives in the topology tree rather than the policy
...               tree. Asserting 'formed' produces a false failure on every
...               binding. Hardware programming is the reliable signal.
...
...               CHANGED_PATHS can narrow execution to the bindings touched by
...               this change, matched on full DN. Not wired into the pipeline:
...               these are 13 sub-second API calls, so scoping saves nothing and
...               a full sweep is the stronger statement. Leaving the variable
...               unset runs everything.
Suite Setup       Login APIC
Test Tags         apic    day2    operational    tenants    static-ports
Resource          ../../apic_common.resource
Library           String

*** Variables ***
# Comma-separated tDn values from plan.json, e.g.
#   topology/pod-1/protpaths-1101-1102/pathep-[vpc-ucs-prod-01-6454-A]
# Read from the environment: nac-test rejects --variable (Click exits 2 with
# "No such option"), and %{} keeps everything off the command line.
${CHANGED_PATHS}    %{CHANGED_PATHS=}

*** Keywords ***
Path Is In Scope
    [Documentation]    True when CHANGED_PATHS is empty (full sweep) or this
    ...                path's FULL DN appears in it.
    ...
    ...                Matches on the full DN, not the tDn. A tDn such as
    ...                topology/pod-1/protpaths-1101-1102/pathep-[vpc-ucs-prod-01-6454-A]
    ...                is shared by every EPG bound to that vPC, so scoping on it
    ...                would match sibling EPGs and run tests that were never
    ...                part of the change. The DN includes /epg-<name>/ and is
    ...                therefore unique per binding.
    ...
    ...                Uses $var rather than '${var}' - DNs contain brackets, and
    ...                the '${}' form substitutes them into the Python expression
    ...                source.
    [Arguments]    ${full_dn}
    ${raw}=    Strip String    ${CHANGED_PATHS}
    IF    $raw == ''
        RETURN    ${True}
    END
    ${hit}=    Evaluate
    ...    any(t.strip() == $full_dn for t in $raw.split(',') if t.strip())
    RETURN    ${hit}

Relation State Should Not Be Missing Target
    [Documentation]    On this fabric fvRsPathAtt.state reads 'unformed' for
    ...                working vPC static paths - verified against
    ...                vlanCktEp operSt=up / hwId=120 for the same EPG and encap.
    ...                The target fabricPathEp lives in the topology tree rather
    ...                than the policy tree, so the APIC does not mark the
    ...                relation formed even when the path is deployed.
    ...
    ...                Asserting state=formed would therefore produce a false
    ...                failure on every binding. Only 'missing-target' is treated
    ...                as an error: that state means the referenced vPC or
    ...                interface policy group genuinely does not exist. Any other
    ...                non-formed value is logged for visibility.
    [Arguments]    ${response}    ${label}
    ${states}=    Get Value From Json    ${response}    $..fvRsPathAtt.attributes.state
    ${n}=    Get Length    ${states}
    IF    ${n} == 0
        RETURN
    END
    ${state}=    Set Variable    ${states}[0]
    IF    $state == 'missing-target'
        ${quals}=    Get Value From Json    ${response}    $..fvRsPathAtt.attributes.stateQual
        ${nq}=    Get Length    ${quals}
        ${qual}=    Set Variable If    ${nq} > 0    ${quals}[0]    <none>
        Run Keyword And Continue On Failure    Fail
        ...    ${label}: relation state is 'missing-target' (stateQual=${qual}) - the referenced vPC or interface policy group does not exist, so this path carries no traffic.
    ELSE IF    $state != 'formed'
        Log    ${label}: relation state is '${state}' - expected on this fabric for vPC paths, hardware programming is asserted separately    INFO
    END

*** Test Cases ***
{% set tenant = ((apic | default()) | community.general.json_query('tenants[?name==`' ~ item[2] ~ '`]'))[0] %}
{% for ap in tenant.application_profiles | default([]) %}
{% set ap_name = ap.name ~ defaults.apic.tenants.application_profiles.name_suffix %}
{% for epg in ap.endpoint_groups | default([]) %}
{% set epg_name = epg.name ~ defaults.apic.tenants.application_profiles.endpoint_groups.name_suffix %}

{% if epg.static_ports is defined %}
Verify EPG {{ epg_name }} Deployed Path Count
    [Documentation]    Every configured static path must resolve to a deployed
    ...                path. A missing path means that UCS domain has no
    ...                connectivity for this segment.
    ...
    ...                This is an EXACT equality check, so it also detects paths
    ...                added to the EPG outside the data model. That is drift
    ...                detection rather than a change check - deliberate, but if
    ...                anyone binds a path by hand this test fails. Exclude the
    ...                epg-path-count tag if that is not wanted.
    ...
    ...                Deliberately NOT scoped by CHANGED_PATHS: it is an
    ...                aggregate over the whole EPG, not a per-path assertion.
    [Tags]    epg-path-count
    ${r}=    GET On Session    apic
    ...    /api/node/mo/uni/tn-{{ tenant.name }}/ap-{{ ap_name }}/epg-{{ epg_name }}.json
    ...    params=query-target=children&target-subtree-class=fvRsPathAtt
    Set Suite Variable    $r    ${r.json()}
    ${configured}=    Get Value From Json    ${r}    $.totalCount
    IF    ${configured}[0] != {{ epg.static_ports | length }}
        Run Keyword And Continue On Failure    Fail
        ...    {{ epg_name }}: {{ epg.static_ports | length }} static ports in data model but ${configured}[0] on APIC
    END

{% for sp in epg.static_ports | default([]) %}
{%- set query = "nodes[?id==`" ~ sp.node_id ~ "`].pod" %}
{%- set pod = sp.pod_id | default(((apic.node_policies | default()) | community.general.json_query(query))[0] | default('1')) %}
{#- Path endpoint: a channel (PC/vPC) name, else eth<module>/<port> for an   -#}
{#- access port. The original template assumed sp.channel was always         -#}
{#- defined, which renders 'pathep-[]' for an access port and produces a     -#}
{#- test that can never pass.                                               -#}
{%- if sp.channel is defined %}
{%-   set pathep = sp.channel %}
{%- elif sp.port is defined %}
{%-   set pathep = "eth" ~ (sp.module | default(1)) ~ "/" ~ sp.port %}
{%- else %}
{%-   set pathep = "" %}
{%- endif %}
{%- if sp.node2_id is defined %}
{%-   set path_dn = "topology/pod-" ~ pod ~ "/protpaths-" ~ sp.node_id ~ "-" ~ sp.node2_id ~ "/pathep-[" ~ pathep ~ "]" %}
{%- else %}
{%-   set path_dn = "topology/pod-" ~ pod ~ "/paths-" ~ sp.node_id ~ "/pathep-[" ~ pathep ~ "]" %}
{%- endif %}
{%- if pathep != "" %}

Verify EPG {{ epg_name }} Path {{ pathep }} VLAN {{ sp.vlan }} Deployed
    [Documentation]    Static path {{ path_dn }}
    ...                on EPG {{ epg_name }}, encap vlan-{{ sp.vlan }}.
    ...
    ...                Checks the MO is present, that the relation is not
    ...                missing-target, and that the encap on APIC matches the
    ...                data model.
    ${in_scope}=    Path Is In Scope
    ...    uni/tn-{{ tenant.name }}/ap-{{ ap_name }}/epg-{{ epg_name }}/rspathAtt-[{{ path_dn }}]
    Skip If    not ${in_scope}
    ...    {{ pathep }} is not part of this change (CHANGED_PATHS=${CHANGED_PATHS})
    ${r}=    GET On Session    apic
    ...    /api/node/mo/uni/tn-{{ tenant.name }}/ap-{{ ap_name }}/epg-{{ epg_name }}/rspathAtt-[{{ path_dn }}].json
    Set Suite Variable    $r    ${r.json()}
    ${count}=    Get Value From Json    ${r}    $.totalCount
    IF    ${count}[0] == 0
        Run Keyword And Continue On Failure    Fail
        ...    {{ epg_name }}: static path {{ pathep }} is not present on APIC
    ELSE
        Relation State Should Not Be Missing Target    ${r}    {{ epg_name }} path {{ pathep }}
        ${encaps}=    Get Value From Json    ${r}    $..fvRsPathAtt.attributes.encap
        ${ne}=    Get Length    ${encaps}
        IF    ${ne} > 0 and "${encaps}[0]" != "vlan-{{ sp.vlan }}"
            Run Keyword And Continue On Failure    Fail
            ...    {{ epg_name }} path {{ pathep }}: encap is ${encaps}[0] on APIC but vlan-{{ sp.vlan }} in the data model
        END
    END

{%- endif %}
{% endfor %}
{% endif %}
{% endfor %}
{% endfor %}