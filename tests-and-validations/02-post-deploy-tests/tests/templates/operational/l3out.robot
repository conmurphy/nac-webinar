{# iterate_list apic.tenants name item[2] #}
*** Settings ***
Documentation   Verify L3out Operational State
Suite Setup     Login APIC
Default Tags    apic   day2   operational   tenants   l3out
Resource        ../../apic_common.resource

*** Test Cases ***
{% set tenant = ((apic | default()) | community.general.json_query('tenants[?name==`' ~ item[2] ~ '`]'))[0] %}
{% for l3out in tenant.l3outs | default([]) %}
{% set l3out_name = l3out.name ~ defaults.apic.tenants.l3outs.name_suffix %}
{% set vrf_name = l3out.vrf ~ ('' if l3out.vrf in ('inb', 'obb', 'overlay-1') else defaults.apic.tenants.vrfs.name_suffix) %}
{% for np in l3out.node_profiles | default([]) %}
{% for ip_prof in np.interface_profiles | default([]) %}
{% for int in ip_prof.interfaces | default([]) %}
{% set if_idx = loop.index %}
{% set query = "nodes[?id==`" ~ int.node_id ~ "`].pod" %}
{% set pod = int.pod_id | default(((apic.node_policies | default()) | community.general.json_query(query))[0] | default('1')) %}
{% set node_list = [int.node_id] %}
{% if int.node2_id is defined %}
{% set node_list = [int.node_id, int.node2_id] %}
{% endif %}
{% for peer in int.bgp_peers | default([]) %}
{# ACI stores the peer container as peer-[<configured prefix>] for BOTH static
   peers and dynamic/listen ranges. The bgpPeerEntry children are the actual
   sessions - for a static peer the entry matches the configured IP, for a
   dynamic range it is whichever peer connected. So query the container and
   assert at least one child session is established. #}
{% set peer_prefix = peer.ip if '/' in peer.ip else peer.ip ~ '/32' %}
{% for node in node_list %}

Verify Established Session For L3out {{ l3out_name }} BGP Peer {{ peer_prefix }} Node {{ node }} Interface {{ if_idx }}
    [Documentation]    VRF {{ tenant.name }}:{{ vrf_name }}. Asserts at least one
    ...                established session under peer-[{{ peer_prefix }}].
    ...                Works for static peers and dynamic listen ranges alike.
    ${r}=   GET On Session   apic   /api/node/mo/topology/pod-{{ pod }}/node-{{ node }}/sys/bgp/inst/dom-{{ tenant.name }}:{{ vrf_name }}/peer-[{{ peer_prefix }}].json   params=rsp-subtree=children&rsp-subtree-class=bgpPeerEntry
    Set Suite Variable   $r   ${r.json()}
    ${count}=   Get Value From Json   ${r}   $.totalCount
    IF    ${count}[0] == 0
        Run Keyword And Continue On Failure    Fail
        ...    "Node {{ node }}: BGP peer config {{ peer_prefix }} not found in VRF {{ tenant.name }}:{{ vrf_name }}"
    ELSE
        @{states}=   Get Value From Json   ${r}   $..bgpPeerEntry.attributes.operSt
        ${sessions}=   Get Length   ${states}
        IF    ${sessions} == 0
            Run Keyword And Continue On Failure    Fail
            ...    "Node {{ node }} peer {{ peer_prefix }}: configured but no BGP sessions have formed"
        ELSE
            @{addrs}=   Get Value From Json   ${r}   $..bgpPeerEntry.attributes.addr
            Log    Sessions under {{ peer_prefix }}: ${addrs} states=${states}
            ${established}=   Evaluate   [s for s in $states if s == 'established']
            ${est_count}=   Get Length   ${established}
            IF    ${est_count} == 0
                Run Keyword And Continue On Failure    Fail
                ...    "Node {{ node }} peer {{ peer_prefix }}: no established sessions - peers ${addrs} are in state ${states}"
            END
        END
    END

{% set bfd = peer.bfd | default('no') %}
{% if bfd == 'yes' %}

Verify L3out {{ l3out_name }} BFD Peer {{ peer_prefix }} Node {{ node }} Interface {{ if_idx }}
    ${r}=   GET On Session   apic   /api/node/mo/topology/pod-{{ pod }}/node-{{ node }}/sys/bfd/inst.json   params=query-target=children&query-target-filter=eq(bfdSess.vrfName,"{{ tenant.name }}:{{ vrf_name }}")
    Set Suite Variable   $r   ${r.json()}
    ${count}=   Get Value From Json   ${r}   $.totalCount
    IF    ${count}[0] == 0
        Run Keyword And Continue On Failure    Fail
        ...    "Node {{ node }}: no BFD sessions in VRF {{ tenant.name }}:{{ vrf_name }}"
    ELSE
        @{states}=   Get Value From Json   ${r}   $..bfdSess.attributes.operSt
        ${up}=   Evaluate   [s for s in $states if s == 'up']
        ${up_count}=   Get Length   ${up}
        IF    ${up_count} == 0
            Run Keyword And Continue On Failure    Fail
            ...    "Node {{ node }}: no BFD sessions up in VRF {{ tenant.name }}:{{ vrf_name }} (states ${states})"
        END
    END
{% endif %}

{% endfor %}{# node in node_list #}
{% endfor %}{# peer in int.bgp_peers #}
{% endfor %}{# int in ip_prof.interfaces #}
{% endfor %}{# ip_prof in np.interface_profiles #}
{% endfor %}{# np in l3out.node_profiles #}
{% endfor %}{# l3out in tenant.l3outs #}