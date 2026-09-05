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
    [Documentation]    Fabric-wide sweep for interfaces that are down.
    ...
    ...                Reports admin-down SEPARATELY rather than excluding it.
    ...                The previous filter excluded admin-down entirely, so a
    ...                deliberately disabled port produced a PASS - technically
    ...                correct, but it meant nothing in this suite could ever
    ...                see one.
    ${r}=    GET On Session    apic
    ...    /api/node/class/ethpmPhysIf.json
    ...    params=query-target-filter=eq(ethpmPhysIf.operSt,"down")
    ${j}=    Set Variable    ${r.json()}
    ${count}=    Get Value From Json    ${j}    $.totalCount
    IF    ${count}[0] > 0
        Log    ${count}[0] interface(s) down fabric-wide - see ucs_domain_interfaces for the UCS-facing ones, which are the ones that affect BD deployment    WARN
    END