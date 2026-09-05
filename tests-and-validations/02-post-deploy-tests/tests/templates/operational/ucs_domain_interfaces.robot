*** Settings ***
Documentation       Verify the leaf interfaces facing each UCS domain are up.
...
...                 WHY THIS EXISTS ALONGSIDE THE vPC TEST
...                 The vPC suite reports that a bundle is down on one or both
...                 peers. It does not say which member interface, nor why. This
...                 suite checks each physical member and separates the two
...                 causes that need completely different responses:
...
...                   adminSt down  - somebody disabled the port, or it is
...                                   blacklisted via fabricRsOosPath. A config
...                                   action, reversible in the APIC UI.
...                   operSt down   - the port is configured up but the link is
...                                   not forming. Cable, transceiver, or the
...                                   UCS fabric interconnect side.
...
...                 WHY IT MATTERS BEYOND THE UCS DOMAIN ITSELF
...                 A bridge domain is only deployed on a leaf where an EPG has
...                 an OPERATIONAL static path. If both UCS legs on a leaf are
...                 down, the pervasive SVI is not programmed there, and a
...                 fabric-sourced ping from the BD gateway on that leaf fails
...                 with "% Invalid source address" - which reads like a routing
...                 fault but is really this.
...
...                 SOURCE OF TRUTH
...                 UCS_DOMAINS below is a hardcoded map, not derived from the
...                 data model. The bundle-to-physical-port mapping lives in
...                 infraPortBlk under the port selectors and is not expressed in
...                 the NaC YAML, so it cannot be rendered from it. It IS
...                 duplicated in the nac-validate rules
...                 (204_static_port_domain_coverage.py and
...                 210_static_paths_prod_only.py) - grep for DUPLICATED-IN
...                 before editing any copy.
Suite Setup         Login APIC
Test Tags           apic    day2    operational    post-check    ucs-domain
Resource            ../apic_common.resource

*** Variables ***
# Single-pod fabric; every DN observed on this system is under pod-1. Overridable
# so a multi-pod change does not require editing the queries.
${UCS_POD}    1

*** Test Cases ***
{#- ══════════════════════════════════════════════════════════════════ -#}
{#- DUPLICATED-IN: nac-validate 204_static_port_domain_coverage.py     -#}
{#- DUPLICATED-IN: nac-validate 210_static_paths_prod_only.py          -#}
{#-                                                                    -#}
{#- Sourced from:                                                      -#}
{#-   moquery -c infraPortBlk -f 'infra.PortBlk.dn*"6454"'             -#}
{#-   moquery -c infraPortBlk -f 'infra.PortBlk.dn*"6536"'             -#}
{#- Every block was single-port (fromPort == toPort) and symmetric      -#}
{#- across both leaves, which is why one interface per bundle is        -#}
{#- sufficient here. A multi-port block would need a list.             -#}
{#-                                                                    -#}
{#- NOTE node 1201 also has eth1/11-1/18 populated but is NOT a UCS     -#}
{#- leaf. Scope is therefore by explicit node list, never by            -#}
{#- interface id alone.                                                -#}
{#- ══════════════════════════════════════════════════════════════════ -#}
{%- set ucs_leaf_nodes = ['1101', '1102'] %}
{%- set ucs_domains = {
      'prod': {
        'vpc-ucs-prod-01-6454-A': '1/15',
        'vpc-ucs-prod-01-6454-B': '1/16'
      },
      'test': {
        'vpc-ucs-test-01-6536-A': '1/11',
        'vpc-ucs-test-01-6536-B': '1/12'
      },
      'sandbox': {
        'vpc-ucs-sandbox-01-6454-A': '1/17',
        'vpc-ucs-sandbox-01-6454-B': '1/18'
      }
    } %}

{%- for domain, bundles in ucs_domains.items() %}
{%- for bundle, port in bundles.items() %}
{%- for node in ucs_leaf_nodes %}
{%- set ifname = 'eth' ~ port %}

Verify {{ domain | upper }} UCS Interface {{ ifname }} On Node {{ node }} Is Up
    [Documentation]    Physical member of {{ bundle }} on leaf {{ node }}.
    ...
    ...                Two reads, because they answer different questions:
    ...                  l1PhysIf.adminSt     - is it configured up?
    ...                  ethpmPhysIf.operSt   - is it actually up?
    ...
    ...                A pass proves this leg of the {{ domain }} UCS vPC can
    ...                carry traffic, and therefore that a BD with a static path
    ...                to {{ bundle }} will be deployed on this leaf.
    [Tags]    ucs-{{ domain }}    interfaces
    ${cfg}=    GET On Session    apic
    ...    /api/node/mo/topology/pod-${UCS_POD}/node-{{ node }}/sys/phys-[{{ ifname }}].json
    ${cfg_json}=    Set Variable    ${cfg.json()}
    ${cfg_count}=    Get Value From Json    ${cfg_json}    $.totalCount
    IF    ${cfg_count}[0] == 0
        Run Keyword And Continue On Failure    Fail
        ...    Node {{ node }} {{ ifname }} does not exist in the MIT - check that the interface is present on this leaf and that UCS_DOMAINS is accurate
        RETURN
    END

    ${admin}=    Get Value From Json    ${cfg_json}    $..l1PhysIf.attributes.adminSt
    ${switching}=    Get Value From Json    ${cfg_json}    $..l1PhysIf.attributes.switchingSt

    ${st}=    GET On Session    apic
    ...    /api/node/mo/topology/pod-${UCS_POD}/node-{{ node }}/sys/phys-[{{ ifname }}]/phys.json
    ${st_json}=    Set Variable    ${st.json()}
    ${oper}=    Get Value From Json    ${st_json}    $..ethpmPhysIf.attributes.operSt
    ${qual}=    Get Value From Json    ${st_json}    $..ethpmPhysIf.attributes.operStQual

    Log    {{ domain }} {{ bundle }} node {{ node }} {{ ifname }}: adminSt=${admin}[0] switchingSt=${switching}[0] operSt=${oper}[0] (${qual}[0])

    # adminSt first. When the port has been disabled, operSt is down as a
    # CONSEQUENCE, and reporting the consequence sends the reader to the cabling
    # rather than to whoever shut the port.
    IF    "${admin}[0]" != "up"
        Run Keyword And Continue On Failure    Fail
        ...    {{ domain | upper }} UCS interface {{ ifname }} on node {{ node }} ({{ bundle }}) is ADMINISTRATIVELY DOWN (adminSt=${admin}[0]). Somebody disabled the port, or it is blacklisted out of service. Re-enable it in Fabric > Inventory, or remove the out-of-service entry. This is a config action, not a cabling fault.
    ELSE IF    "${oper}[0]" != "up"
        Run Keyword And Continue On Failure    Fail
        ...    {{ domain | upper }} UCS interface {{ ifname }} on node {{ node }} ({{ bundle }}) is configured up but operSt=${oper}[0] (${qual}[0]). The port is enabled and the link is not forming - check the transceiver, the cable, and the UCS fabric interconnect side.
    END

{%- endfor %}
{%- endfor %}
{%- endfor %}

{#- ── per-node redundancy roll-up ───────────────────────────────────── -#}
{#- The per-interface tests above say WHICH leg is broken. These say     -#}
{#- whether it MATTERS: one leg down is degraded and survivable, both    -#}
{#- legs down on a leaf means the BD is not deployed there at all.       -#}
{%- for domain, bundles in ucs_domains.items() %}
{%- for node in ucs_leaf_nodes %}

Verify Node {{ node }} Retains A Path To The {{ domain | upper }} UCS Domain
    [Documentation]    Fails only when EVERY leg from leaf {{ node }} to the
    ...                {{ domain }} UCS domain is down.
    ...
    ...                This is the outage-versus-degraded distinction. A single
    ...                leg down is reported by the per-interface test above and
    ...                is survivable. Zero legs up means no EPG static path on
    ...                this leaf is operational, so the bridge domain is not
    ...                deployed here and its pervasive SVI does not exist - the
    ...                gateway will not answer and will not be usable as an
    ...                iping source on this node.
    [Tags]    ucs-{{ domain }}    redundancy
    ${up}=    Set Variable    ${0}
    ${detail}=    Create List
{%- for bundle, port in bundles.items() %}
{%- set ifname = 'eth' ~ port %}
    ${r}=    GET On Session    apic
    ...    /api/node/mo/topology/pod-${UCS_POD}/node-{{ node }}/sys/phys-[{{ ifname }}]/phys.json
    ...    expected_status=any
    ${j}=    Set Variable    ${r.json()}
    ${c}=    Get Value From Json    ${j}    $.totalCount
    IF    ${c}[0] > 0
        ${o}=    Get Value From Json    ${j}    $..ethpmPhysIf.attributes.operSt
        Append To List    ${detail}    {{ ifname }}=${o}[0]
        IF    "${o}[0]" == "up"
            ${up}=    Evaluate    ${up} + 1
        END
    ELSE
        Append To List    ${detail}    {{ ifname }}=absent
    END
{%- endfor %}
    Log    node {{ node }} {{ domain }} legs: ${detail} (${up} up)
    IF    ${up} == 0
        Run Keyword And Continue On Failure    Fail
        ...    Leaf {{ node }} has NO operational interface to the {{ domain | upper }} UCS domain (${detail}). Every EPG static path to this domain on this leaf is down, so any bridge domain relying on it is not deployed here and its gateway will not respond from this node.
    END

{%- endfor %}
{%- endfor %}