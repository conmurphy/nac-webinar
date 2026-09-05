*** Settings ***
Documentation     Verify vPC Domain And Member Interface State
Suite Setup       Login APIC
Default Tags      apic    day2    operational    post-check    vpc 
Resource          ../apic_common.resource

*** Test Cases ***
{% for group in apic.node_policies.vpc_groups.groups | default([]) %}
{% for switch in group.switches | default([]) %}
{% set query = "nodes[?id==`" ~ switch.node_id ~ "`].pod" %}
{% set pod = switch.pod_id | default(((apic.node_policies | default()) | community.general.json_query(query))[0] | default('1')) %}

Verify Node {{ switch.node_id }} vPC Domain {{ group.id }} Peer State
    ${r}=    GET On Session    apic    /api/node/mo/topology/pod-{{ pod }}/node-{{ switch.node_id }}/sys/vpc/inst/dom-{{ group.id }}.json
    Set Suite Variable    $r    ${r.json()}
    ${count}=    Get Value From Json    ${r}    $.totalCount
    Run Keyword If    ${count}[0] == 0    Run Keyword And Continue On Failure
    ...    Fail    "Node {{ switch.node_id }}: vPC domain {{ group.id }} not found"
    ${peer_st}=    Get Value From Json    ${r}    $..vpcDom.attributes.peerSt
    ${peer_qual}=    Get Value From Json    ${r}    $..vpcDom.attributes.peerStQual
    ${compat}=    Get Value From Json    ${r}    $..vpcDom.attributes.compatSt
    ${dual}=    Get Value From Json    ${r}    $..vpcDom.attributes.dualActiveSt
    ${role}=    Get Value From Json    ${r}    $..vpcDom.attributes.operRole
    Run Keyword If    ${count}[0] > 0 and "${peer_st}[0]" != "up"    Run Keyword And Continue On Failure
    ...    Fail    "Node {{ switch.node_id }} vPC dom {{ group.id }}: peerSt is ${peer_st}[0] (${peer_qual}[0]), expected up"
    Run Keyword If    ${count}[0] > 0 and "${compat}[0]" != "pass"    Run Keyword And Continue On Failure
    ...    Fail    "Node {{ switch.node_id }} vPC dom {{ group.id }}: consistency check is ${compat}[0], expected pass"
    Run Keyword If    ${count}[0] > 0 and "${dual}[0]" != "false"    Run Keyword And Continue On Failure
    ...    Fail    "Node {{ switch.node_id }} vPC dom {{ group.id }}: DUAL ACTIVE (split brain) detected"
    Run Keyword If    ${count}[0] > 0 and "${role}[0]" == "unknown"    Run Keyword And Continue On Failure
    ...    Fail    "Node {{ switch.node_id }} vPC dom {{ group.id }}: operRole is unknown"

{% endfor %}
{% endfor %}

{# --- one test per unique vPC bundle used by any static port --- #}
{% set seen = [] %}
{% for tenant in apic.tenants | default([]) %}
{% for ap in tenant.application_profiles | default([]) %}
{% for epg in ap.endpoint_groups | default([]) %}
{% for sp in epg.static_ports | default([]) %}
{% if sp.channel is defined and sp.channel not in seen %}
{% set _ = seen.append(sp.channel) %}

Verify vPC {{ sp.channel }} Is Up On Both Peers
    [Documentation]    Queried by name so both leaf entries are returned.
    ...                localOperSt/remoteOperSt must be up on both, and no
    ...                VLANs may be suspended by consistency check.
    ${r}=    GET On Session    apic
    ...    /api/node/class/vpcIf.json
    ...    params=query-target-filter=eq(vpcIf.name,"{{ sp.channel }}")
    Set Suite Variable    $r    ${r.json()}
    ${count}=    Get Value From Json    ${r}    $.totalCount
    Run Keyword If    ${count}[0] == 0    Run Keyword And Continue On Failure
    ...    Fail    "vPC bundle {{ sp.channel }} not found on any leaf"
    Run Keyword If    ${count}[0] == 1    Run Keyword And Continue On Failure
    ...    Fail    "vPC bundle {{ sp.channel }} present on only one leaf (expected 2)"
    @{local}=     Get Value From Json    ${r}    $..vpcIf.attributes.localOperSt
    @{remote}=    Get Value From Json    ${r}    $..vpcIf.attributes.remoteOperSt
    @{susp}=      Get Value From Json    ${r}    $..vpcIf.attributes.suspVlans
    FOR    ${s}    IN    @{local}
        Run Keyword If    "${s}" != "up"    Run Keyword And Continue On Failure
        ...    Fail    "{{ sp.channel }}: localOperSt is ${s}, expected up"
    END
    FOR    ${s}    IN    @{remote}
        Run Keyword If    "${s}" != "up"    Run Keyword And Continue On Failure
        ...    Fail    "{{ sp.channel }}: remoteOperSt is ${s}, expected up"
    END
    FOR    ${s}    IN    @{susp}
        Run Keyword If    "${s}" != ""    Run Keyword And Continue On Failure
        ...    Fail    "{{ sp.channel }}: VLANs suspended by consistency check: ${s}"
    END

{% endif %}
{% endfor %}
{% endfor %}
{% endfor %}
{% endfor %}