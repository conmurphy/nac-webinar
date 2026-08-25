{# iterate_list apic.tenants name item[2] #}
*** Settings ***
Documentation     Verify EPG Static Path Deployment
Suite Setup       Login APIC
Default Tags      apic    day2    operational    tenants    static-ports 
Resource          ../../apic_common.resource

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
    ${r}=    GET On Session    apic
    ...    /api/node/mo/uni/tn-{{ tenant.name }}/ap-{{ ap_name }}/epg-{{ epg_name }}.json
    ...    params=query-target=children&target-subtree-class=fvRsPathAtt
    Set Suite Variable    $r    ${r.json()}
    ${configured}=    Get Value From Json    ${r}    $.totalCount
    Run Keyword If    ${configured}[0] != {{ epg.static_ports | length }}    Run Keyword And Continue On Failure
    ...    Fail    "{{ epg_name }}: {{ epg.static_ports | length }} static ports in data model but ${configured}[0] on APIC"

{% for sp in epg.static_ports | default([]) %}
{% set query = "nodes[?id==`" ~ sp.node_id ~ "`].pod" %}
{% set pod = sp.pod_id | default(((apic.node_policies | default()) | community.general.json_query(query))[0] | default('1')) %}
{% if sp.node2_id is defined %}
{% set path_dn = "topology/pod-" ~ pod ~ "/protpaths-" ~ sp.node_id ~ "-" ~ sp.node2_id ~ "/pathep-[" ~ sp.channel ~ "]" %}
{% else %}
{% set path_dn = "topology/pod-" ~ pod ~ "/paths-" ~ sp.node_id ~ "/pathep-[" ~ sp.channel ~ "]" %}
{% endif %}

Verify EPG {{ epg_name }} Path {{ sp.channel }} VLAN {{ sp.vlan }} Deployed
    ${r}=    GET On Session    apic
    ...    /api/node/mo/uni/tn-{{ tenant.name }}/ap-{{ ap_name }}/epg-{{ epg_name }}/rspathAtt-[{{ path_dn }}].json
    Set Suite Variable    $r    ${r.json()}
    ${count}=    Get Value From Json    ${r}    $.totalCount
    Run Keyword If    ${count}[0] == 0    Run Keyword And Continue On Failure
    ...    Fail    "{{ epg_name }}: static path {{ sp.channel }} is not present on APIC"

{% endfor %}
{% endif %}
{% endfor %}
{% endfor %}