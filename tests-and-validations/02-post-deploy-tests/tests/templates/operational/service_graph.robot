{# iterate_list apic.tenants name item[2] #}
*** Settings ***
Documentation     Verify L4-L7 Service Graph And Device State
Suite Setup       Login APIC
Default Tags      apic    day2    operational    post-check    services 
Resource          ../../apic_common.resource

*** Test Cases ***
{% set tenant = ((apic | default()) | community.general.json_query('tenants[?name==`' ~ item[2] ~ '`]'))[0] %}
{% for dev in tenant.services.l4l7_devices | default([]) %}

Verify L4-L7 Device {{ dev.name }} Is Operational
    ${r}=    GET On Session    apic
    ...    /api/node/class/vnsCDev.json
    ...    params=query-target-filter=wcard(vnsCDev.dn,"tn-{{ tenant.name }}/lDevVip-{{ dev.name }}")
    Set Suite Variable    $r    ${r.json()}
    ${count}=    Get Value From Json    ${r}    $.totalCount
    Run Keyword If    ${count}[0] == 0    Run Keyword And Continue On Failure
    ...    Fail    "L4-L7 concrete device for {{ dev.name }} not found"

Verify L4-L7 Device {{ dev.name }} Has No Faults
    ${r}=    GET On Session    apic    /api/node/mo/uni/tn-{{ tenant.name }}/lDevVip-{{ dev.name }}/fltCnts.json
    Set Suite Variable    $r    ${r.json()}
    ${critical}=    Json Search String    ${r}    imdata[0].faultCounts.attributes.crit
    ${major}=       Json Search String    ${r}    imdata[0].faultCounts.attributes.maj
    Run Keyword If    ${critical} > 0    Run Keyword And Continue On Failure
    ...    Fail    "L4-L7 device {{ dev.name }} has ${critical} critical fault(s)"
    Run Keyword If    ${major} > 0    Run Keyword And Continue On Failure
    ...    Fail    "L4-L7 device {{ dev.name }} has ${major} major fault(s)"

{% endfor %}

{% for graph in tenant.services.service_graph_templates | default([]) %}

Verify Service Graph {{ graph.name }} Instances Are Applied
    [Documentation]    A graph instance not in 'applied' state means the
    ...                redirect is not programmed and traffic is dropped.
    ${r}=    GET On Session    apic
    ...    /api/node/class/vnsGraphInst.json
    ...    params=query-target-filter=wcard(vnsGraphInst.dn,"tn-{{ tenant.name }}")
    Set Suite Variable    $r    ${r.json()}
    ${count}=    Get Value From Json    ${r}    $.totalCount
    Run Keyword If    ${count}[0] == 0    Run Keyword And Continue On Failure
    ...    Fail    "No service graph instances found in tenant {{ tenant.name }}"
    @{states}=    Get Value From Json    ${r}    $..vnsGraphInst.attributes.configSt
    FOR    ${s}    IN    @{states}
        Run Keyword If    "${s}" != "applied"    Run Keyword And Continue On Failure
        ...    Fail    "Service graph instance configSt is ${s}, expected applied"
    END

{% endfor %}

{% for pol in tenant.services.redirect_policies | default([]) %}
{% for dest in pol.l3_destinations | default([]) %}

Verify Redirect Destination {{ dest.ip }} Is Reachable
    [Documentation]    PBR destination tracking - if the firewall data interface
    ...                is not learned, redirected traffic is dropped or bypassed.
    ${r}=    GET On Session    apic
    ...    /api/node/class/vnsRedirectDest.json
    ...    params=query-target-filter=eq(vnsRedirectDest.ip,"{{ dest.ip }}")
    Set Suite Variable    $r    ${r.json()}
    ${count}=    Get Value From Json    ${r}    $.totalCount
    Run Keyword If    ${count}[0] == 0    Run Keyword And Continue On Failure
    ...    Fail    "Redirect destination {{ dest.ip }} not found"

{% endfor %}
{% endfor %}