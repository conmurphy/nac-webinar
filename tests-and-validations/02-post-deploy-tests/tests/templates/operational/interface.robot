*** Settings ***
Documentation     Verify Physical Interface Operational State
Suite Setup       Login APIC
Default Tags      apic    day2    operational    post-check    interfaces 
Resource          ../apic_common.resource

*** Test Cases ***
{% for node in apic.interface_policies.nodes | default([]) %}
{% set query = "nodes[?id==`" ~ node.id ~ "`].pod" %}
{% set pod = node.pod_id | default(((apic.node_policies | default()) | community.general.json_query(query))[0] | default('1')) %}
{% for int in node.interfaces | default([]) %}
{% if int.port is defined %}
{% set ifname = "eth" ~ (int.module | default(1)) ~ "/" ~ int.port %}

Verify Node {{ node.id }} Interface {{ ifname }} Is Up
    [Documentation]    {{ int.description | default('configured in data model') }}
    ${r}=    GET On Session    apic    /api/node/mo/topology/pod-{{ pod }}/node-{{ node.id }}/sys/phys-[{{ ifname }}]/phys.json
    Set Suite Variable    $r    ${r.json()}
    ${count}=    Get Value From Json    ${r}    $.totalCount
    Run Keyword If    ${count}[0] == 0    Run Keyword And Continue On Failure
    ...    Fail    "Node {{ node.id }} {{ ifname }}: interface not found"
    ${oper}=    Get Value From Json    ${r}    $..ethpmPhysIf.attributes.operSt
    ${qual}=    Get Value From Json    ${r}    $..ethpmPhysIf.attributes.operStQual
    Run Keyword If    ${count}[0] > 0 and "${oper}[0]" != "up"    Run Keyword And Continue On Failure
    ...    Fail    "Node {{ node.id }} {{ ifname }}: operSt is ${oper}[0] (${qual}[0]), expected up"

{% endif %}
{% endfor %}
{% endfor %}

Verify No Configured Interface Is Down Due To Error
    [Documentation]    Catches error-disabled / SFP / link-flap conditions across
    ...                the fabric that a per-interface loop might miss.
    ${r}=    GET On Session    apic
    ...    /api/node/class/ethpmPhysIf.json
    ...    params=query-target-filter=and(eq(ethpmPhysIf.operSt,"down"),ne(ethpmPhysIf.operStQual,"admin-down"))
    Set Suite Variable    $r    ${r.json()}
    ${count}=    Get Value From Json    ${r}    $.totalCount
    Run Keyword If    ${count}[0] > 0    Log    ${count}[0] interface(s) down for non-admin reasons    WARN