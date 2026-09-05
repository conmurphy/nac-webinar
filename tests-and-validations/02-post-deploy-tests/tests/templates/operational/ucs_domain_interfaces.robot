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
...                 an OPERATIONAL static path. If every leg to a domain on a
...                 leaf is down, the pervasive SVI is not programmed there, and
...                 a fabric-sourced ping from the BD gateway on that leaf fails
...                 with "% Invalid source address" - which reads like a routing
...                 fault but is really this.
...
...                 DOMAIN SCOPING
...                 Only ENFORCED_DOMAINS get a redundancy roll-up. That test
...                 asks "is the BD deployed on this leaf via this domain", and
...                 for a domain no EPG is permitted to bind to, the question is
...                 meaningless - a failure would claim a bridge domain is
...                 undeployed when nothing was ever meant to rely on it.
...
...                 Non-enforced domains still get per-interface checks, because
...                 a down port is a real fabric fact, but they are tagged
...                 baseline so they report as pre-existing state rather than as
...                 impact from the change under test.
...
...                 TEMPLATE WHITESPACE NOTE
...                 nac-test renders with trim_blocks=True. A Jinja BLOCK tag - a
...                 for or if statement, as opposed to a plain expression -
...                 placed inside a test body swallows the newline that separates
...                 the next Robot line, and the two get joined -
...
...                 Every loop and conditional here therefore lives either in a
...                 Robot keyword, or in Jinja ABOVE the test name.
...
...                 SOURCE OF TRUTH
...                 UCS_DOMAINS is a hardcoded map, not derived from the data
...                 model. The bundle-to-physical-port mapping lives in
...                 infraPortBlk under the port selectors and is not expressed in
...                 the NaC YAML, so it cannot be rendered from it. It IS
...                 duplicated in the nac-validate rules - grep for
...                 DUPLICATED-IN before editing any copy.
Library             Collections
Library             String
Suite Setup         Login APIC
Test Tags           apic    day2    operational    post-check    ucs-domain
Resource            ../apic_common.resource

*** Variables ***
# Single-pod fabric; every DN observed on this system is under pod-1. Overridable
# so a multi-pod change does not require editing the queries.
${UCS_POD}    1

*** Keywords ***
Interface Operational State
    [Documentation]    Returns (operSt, present) for one physical interface.
    ...
    ...                Wrapped in Run Keyword And Ignore Error: this is used by
    ...                the redundancy roll-up, where one unreadable interface
    ...                must not abort the assessment of the others.
    [Arguments]    ${node}    ${ifname}
    ${status}    ${resp}=    Run Keyword And Ignore Error
    ...    GET On Session    apic
    ...    /api/node/mo/topology/pod-${UCS_POD}/node-${node}/sys/phys-[${ifname}]/phys.json
    IF    $status != 'PASS'
        Log    read failed for node ${node} ${ifname}: ${resp}    WARN
        RETURN    unreadable    ${False}
    END
    ${j}=    Set Variable    ${resp.json()}
    ${c}=    Get Value From Json    ${j}    $.totalCount
    IF    ${c}[0] == 0
        RETURN    absent    ${False}
    END
    ${o}=    Get Value From Json    ${j}    $..ethpmPhysIf.attributes.operSt
    RETURN    ${o}[0]    ${True}

Count Operational Legs To Domain
    [Documentation]    Counts how many of a domain's interfaces on one leaf are
    ...                operationally up, and returns a per-interface detail list
    ...                for the failure message.
    ...
    ...                Interfaces arrive as ONE comma-separated argument rather
    ...                than as *varargs. Robot separates arguments on two or more
    ...                spaces, so a space-joined list rendered from Jinja would
    ...                be fragile to a single-space slip; a CSV cannot be
    ...                mis-split.
    [Arguments]    ${node}    ${domain}    ${ifnames_csv}
    @{ifnames}=    Split String    ${ifnames_csv}    ,
    ${up}=         Set Variable    ${0}
    ${detail}=     Create List
    FOR    ${ifname}    IN    @{ifnames}
        ${state}    ${present}=    Interface Operational State    ${node}    ${ifname}
        Append To List    ${detail}    ${ifname}=${state}
        IF    ${present} and "${state}" == "up"
            ${up}=    Evaluate    ${up} + 1
        END
    END
    ${detail_str}=    Evaluate    ", ".join($detail)
    Log    node ${node} ${domain} legs: ${detail_str} (${up} up)
    RETURN    ${up}    ${detail_str}

Report Interface State
    [Documentation]    Emits the right failure for an interface that is not up.
    ...
    ...                adminSt is judged FIRST. When a port has been disabled,
    ...                operSt is down as a CONSEQUENCE, and reporting the
    ...                consequence sends the reader to the cabling rather than to
    ...                whoever shut the port.
    ...
    ...                A keyword rather than inline IF/ELSE IF so the test body
    ...                stays free of anything a Jinja block tag could join onto.
    [Arguments]    ${node}    ${ifname}    ${bundle}    ${domain}
    ...    ${admin}    ${oper}    ${qual}
    ${dom}=    Convert To Upper Case    ${domain}
    IF    "${admin}" != "up"
        Run Keyword And Continue On Failure    Fail
        ...    ${dom} UCS interface ${ifname} on node ${node} (${bundle}) is ADMINISTRATIVELY DOWN (adminSt=${admin}). Somebody disabled the port, or it is blacklisted out of service. Re-enable it in Fabric > Inventory, or remove the out-of-service entry. This is a config action, not a cabling fault.
    ELSE IF    "${oper}" != "up"
        Run Keyword And Continue On Failure    Fail
        ...    ${dom} UCS interface ${ifname} on node ${node} (${bundle}) is configured up but operSt=${oper} (${qual}). The port is enabled and the link is not forming - check the transceiver, the cable, and the UCS fabric interconnect side.
    END

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
{#- sufficient. A multi-port block would need a list per bundle.        -#}
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
{#- Domains an EPG is permitted to bind a static path to. MUST match       -#}
{#- ALLOWED_DOMAINS in nac-validate 210_static_paths_prod_only.py: a       -#}
{#- domain enforced there but absent here would deploy bridge domains with -#}
{#- no redundancy check, and the reverse would fail a redundancy test for  -#}
{#- a domain nothing is allowed to use.                                   -#}
{%- set enforced_domains = ['prod'] %}

{#- ── per-interface state, every domain ────────────────────────────── -#}
{%- for domain, bundles in ucs_domains.items() %}
{%- for bundle, port in bundles.items() %}
{%- for node in ucs_leaf_nodes %}
{%- set ifname = 'eth' ~ port %}
{#- Non-enforced domains are informational: a down test/sandbox port is a -#}
{#- genuine fabric fact but cannot affect an EPG in this tenant, because  -#}
{#- no EPG is permitted to bind there. Tagging it baseline keeps it out of -#}
{#- the change-verification verdict while still reporting it.             -#}
{%- set extra_tags = '' if domain in enforced_domains else '    baseline' %}
{%- set enforcement_note = 'EPGs in this tenant are permitted to bind here, so a failure affects bridge domain deployment.' if domain in enforced_domains else 'No EPG in this tenant is permitted to bind here (nac-validate rule 210), so this is fabric hygiene rather than change impact.' %}

Verify {{ domain | upper }} UCS Interface {{ ifname }} On Node {{ node }} Is Up
    [Documentation]    Physical member of {{ bundle }} on leaf {{ node }}.
    ...
    ...                Two reads, because they answer different questions:
    ...                l1PhysIf.adminSt is it configured up, and
    ...                ethpmPhysIf.operSt is it actually up.
    ...
    ...                {{ enforcement_note }}
    [Tags]    ucs-{{ domain }}    interfaces{{ extra_tags }}
    ${cfg}=    GET On Session    apic
    ...    /api/node/mo/topology/pod-${UCS_POD}/node-{{ node }}/sys/phys-[{{ ifname }}].json
    ${cfg_json}=    Set Variable    ${cfg.json()}
    ${cfg_count}=    Get Value From Json    ${cfg_json}    $.totalCount
    Run Keyword And Continue On Failure    Should Be True    ${cfg_count}[0] > 0
    ...    Node {{ node }} {{ ifname }} does not exist in the MIT - check that the interface is present on this leaf and that the UCS_DOMAINS map in this suite is accurate
    Skip If    ${cfg_count}[0] == 0    interface not present, nothing further to assert
    ${admin}=    Get Value From Json    ${cfg_json}    $..l1PhysIf.attributes.adminSt
    ${switching}=    Get Value From Json    ${cfg_json}    $..l1PhysIf.attributes.switchingSt
    ${st}=    GET On Session    apic
    ...    /api/node/mo/topology/pod-${UCS_POD}/node-{{ node }}/sys/phys-[{{ ifname }}]/phys.json
    ${st_json}=    Set Variable    ${st.json()}
    ${oper}=    Get Value From Json    ${st_json}    $..ethpmPhysIf.attributes.operSt
    ${qual}=    Get Value From Json    ${st_json}    $..ethpmPhysIf.attributes.operStQual
    Log    {{ domain }} {{ bundle }} node {{ node }} {{ ifname }}: adminSt=${admin}[0] switchingSt=${switching}[0] operSt=${oper}[0] (${qual}[0])
    Report Interface State    {{ node }}    {{ ifname }}    {{ bundle }}    {{ domain }}
    ...    ${admin}[0]    ${oper}[0]    ${qual}[0]

{%- endfor %}
{%- endfor %}
{%- endfor %}

{#- ── redundancy roll-up, ENFORCED domains only ───────────────────── -#}
{#- Deliberately not rendered for test/sandbox: the assertion is "the BD -#}
{#- is not deployed on this leaf", which is only meaningful for a domain -#}
{#- an EPG is actually allowed to bind to.                              -#}
{%- for domain in enforced_domains %}
{%- if domain in ucs_domains %}
{%- set bundles = ucs_domains[domain] %}
{%- set ifname_csv = bundles.values() | map('regex_replace', '^', 'eth') | join(',') %}
{%- for node in ucs_leaf_nodes %}

Verify Node {{ node }} Retains A Path To The {{ domain | upper }} UCS Domain
    [Documentation]    Fails only when EVERY leg from leaf {{ node }} to the
    ...                {{ domain }} UCS domain is down.
    ...
    ...                This is the outage-versus-degraded distinction. A single
    ...                leg down is reported by the per-interface tests above and
    ...                is survivable. Zero legs up means no EPG static path on
    ...                this leaf is operational, so any bridge domain relying on
    ...                this domain is not deployed here and its pervasive SVI
    ...                does not exist - the gateway will neither answer nor be
    ...                usable as an iping source on this node.
    ...
    ...                Interfaces checked: {{ ifname_csv }}.
    [Tags]    ucs-{{ domain }}    redundancy
    ${up}    ${detail}=    Count Operational Legs To Domain    {{ node }}    {{ domain }}
    ...    {{ ifname_csv }}
    Run Keyword And Continue On Failure    Should Be True    ${up} > 0
    ...    Leaf {{ node }} has NO operational interface to the {{ domain | upper }} UCS domain (${detail}). Every EPG static path to this domain on this leaf is down, so any bridge domain relying on it is not deployed here and its gateway will not respond from this node.

{%- endfor %}
{%- endif %}
{%- endfor %}