*** Settings ***
Documentation     Post-change connectivity verification for the ACI fabric.
...
...               Two vantage points, deliberately kept distinct:
...
...               1. FABRIC-SOURCED - iping executed ON a border leaf, sourced
...                  from the BD anycast gateway. Proves the pervasive SVI is
...                  deployed, unicast routing is on, the subnet is advertised
...                  out the L3Out, the contract permits ICMP, and return
...                  traffic lands. This is the authoritative post-change check.
...
...               2. RUNNER-SOURCED - ping / dig / curl from the CI container.
...                  Valid on this fabric only because every subnet is
...                  public:true behind l3out-to-core-01, so the gateways are
...                  reachable from the cluster pod network. Proves the
...                  north-south path in the opposite direction.
...
...               Test cases are rendered from the data model. A subnet is
...               eligible only when its BD has a VRF, the subnet is public, and
...               border-leaf nodes are resolvable - otherwise no test case is
...               emitted at all. CHANGED_SUBNETS then narrows execution to the
...               subnets touched by this change; when it is empty the full
...               configured set runs as a regression sweep.
...
...               TRANSPORT NOTE: iping is a VSH-hosted wrapper that writes to a
...               controlling terminal. The non-PTY SSH exec channel discards its
...               output while still exiting 0 - verified on this fabric, where
...               exec_command returned exactly '\n\n\n\n\n'. This suite must
...               therefore use Login + Write + Read Until Prompt, which requests
...               a PTY via invoke_shell(). Never use Execute Command here.
Library           Process
Library           Collections
Library           String
Library           SSHLibrary
Suite Setup       Probe Runner Capabilities
Suite Teardown    Close All Connections
Test Tags         apic    day2    operational    traffic

*** Variables ***
# ─── runner-side targets ───
@{DNS_SERVERS}            198.18.194.4    198.18.194.5
@{EXTERNAL_HOSTS}         google.com      cisco.com
${DHCP_SERVER}            198.18.194.4
${CURL_TIMEOUT}           10
${DIG_TIMEOUT}            3
${TCP_TIMEOUT}            5
${DNS_PROBE_NAME}         google.com
${INTERNAL_HTTPS_HOST}    ${EMPTY}

# ─── fabric SSH ───
# Read from the environment. nac-test does not accept --variable directly
# (Click parses it as an unknown option and exits 2), and %{} avoids putting
# anything on a command line at all.
${NODE_MGMT_MAP}          %{NODE_MGMT_MAP=}
# Read from the environment so the secret never appears in a process command
# line. Passing it with --variable would expose it in /proc to anything in the
# same container.
${SWITCH_USER}            %{SWITCH_USER=}
${SWITCH_PASSWORD}        %{SWITCH_PASSWORD=}
# Optional private key. When set, key auth is used and SWITCH_PASSWORD is
# ignored - strongly preferred, see the notes on log.html.
${SWITCH_KEYFILE}         %{SWITCH_KEYFILE=}
${PING_COUNT}             3
# An IP, not a name - the switches are not relied on for DNS resolution.
${FABRIC_EXT_TARGET}      8.8.8.8
# In-band management VRF. Confirm with 'show vrf' on a leaf before trusting.
${MGMT_VRF}               mgmt:inb
# Verified prompt: "cai-emea-site-01-leaf-1101# ". Matched as a regexp so a
# hostname change or a different leaf does not break the read.
${SWITCH_PROMPT}          [\w.\-]+#\s*$
# iping -c 3 takes ~3s; generous headroom for a busy control plane.
${SSH_READ_TIMEOUT}       45s

# ─── change scoping ───
# Comma-separated subnet CIDRs extracted from plan.json, e.g.
#   198.18.215.1/26,198.18.215.65/26
# Empty means "run every configured subnet" (full sweep).
${CHANGED_SUBNETS}        %{CHANGED_SUBNETS=}

# ─── runner -> gateway ICMP ───
# Default enabled: these subnets are public behind the L3Out, so the path
# should work and a failure is a genuine finding. Accepts true/false as a
# string or a boolean - normalised in Suite Setup.
${GATEWAY_PING_ENABLED}   %{GATEWAY_PING_ENABLED=true}

# ─── populated by Suite Setup ───
${ICMP_AVAILABLE}         ${False}
${ICMP_REASON}            ICMP capability not probed
${DIG_AVAILABLE}          ${False}
${SSH_CONFIGURED}         ${False}
${USE_KEY_AUTH}           ${False}
&{NODE_IPS}

*** Keywords ***
Probe Runner Capabilities
    [Documentation]    Establishes once, at suite level, what this container can
    ...                do and which fabric targets are configured.
    Normalise Boolean Flags
    Probe ICMP Capability
    Probe Dig Capability
    Parse Node Management Map
    ${n_nodes}=    Get Length    ${NODE_IPS}
    ${have_cred}=    Evaluate
    ...    bool('''${SWITCH_USER}'''.strip()) and (bool('''${SWITCH_PASSWORD}''') or bool('''${SWITCH_KEYFILE}'''.strip()))
    ${use_key}=    Evaluate    bool('''${SWITCH_KEYFILE}'''.strip())
    Set Suite Variable    ${USE_KEY_AUTH}    ${use_key}
    ${have_ssh}=    Evaluate    ${n_nodes} > 0 and ${have_cred}
    Set Suite Variable    ${SSH_CONFIGURED}    ${have_ssh}
    IF    ${SSH_CONFIGURED}
        ${mode}=    Set Variable If    ${USE_KEY_AUTH}    public key    password
        Log    fabric SSH ready: user=${SWITCH_USER} auth=${mode} nodes=${NODE_IPS}
    ELSE
        Log    NODE_MGMT_MAP / SWITCH_USER / credential not set - fabric iping tests will skip    WARN
    END

Normalise Boolean Flags
    [Documentation]    A --variable override arrives as a STRING, so the literal
    ...                "False" would be truthy in 'not ${FLAG}'. Coerce anything
    ...                falsey-looking to a real boolean.
    ${gp}=    Evaluate
    ...    str('''${GATEWAY_PING_ENABLED}''').strip().lower() not in ('false', '0', 'no', 'off', '')
    Set Suite Variable    ${GATEWAY_PING_ENABLED}    ${gp}

Probe ICMP Capability
    [Documentation]    A ping binary carrying cap_net_raw+ep inside a pod whose
    ...                bounding set lacks NET_RAW makes execve fail with EPERM,
    ...                so Run Process RAISES rather than returning a result.
    ...                That cannot be caught by inspecting stderr - it has to be
    ...                caught around the call.
    ${status}    ${result}=    Run Keyword And Ignore Error
    ...    Run Process    ping    -c    1    -W    1    127.0.0.1
    ...    stdout=PIPE    stderr=PIPE    timeout=10s    on_timeout=terminate
    IF    '${status}' != 'PASS'
        Set Suite Variable    ${ICMP_AVAILABLE}    ${False}
        Set Suite Variable    ${ICMP_REASON}
        ...    ping cannot be executed in this container (NET_RAW dropped): ${result}
        Log    ${ICMP_REASON}    WARN
    ELSE IF    ${result.rc} != 0
        Set Suite Variable    ${ICMP_AVAILABLE}    ${False}
        Set Suite Variable    ${ICMP_REASON}
        ...    ping ran but loopback failed (rc=${result.rc}) - ICMP unusable here
        Log    ${ICMP_REASON}    WARN
    ELSE
        Set Suite Variable    ${ICMP_AVAILABLE}    ${True}
        Log    ICMP is available in this container
    END

Probe Dig Capability
    [Documentation]    dig being absent would silently turn every resolver test
    ...                into a false failure, so detect it and skip instead.
    ${status}    ${result}=    Run Keyword And Ignore Error
    ...    Run Process    dig    -v    stdout=PIPE    stderr=PIPE    timeout=10s
    ${have_dig}=    Evaluate    '${status}' == 'PASS'
    Set Suite Variable    ${DIG_AVAILABLE}    ${have_dig}
    IF    not ${DIG_AVAILABLE}
        Log    dig is not available - resolver-specific tests will skip    WARN
    END

Parse Node Management Map
    [Documentation]    Turns "1101:198.18.192.71,1102:198.18.192.72" into a dict
    ...                keyed by node ID as a string.
    &{map}=    Create Dictionary
    ${raw}=    Strip String    ${NODE_MGMT_MAP}
    IF    '${raw}' != ''
        @{pairs}=    Split String    ${raw}    ,
        FOR    ${pair}    IN    @{pairs}
            ${clean}=    Strip String    ${pair}
            IF    '${clean}' == ''
                CONTINUE
            END
            @{parts}=    Split String    ${clean}    :
            ${n}=    Get Length    ${parts}
            IF    ${n} != 2
                Log    Ignoring malformed NODE_MGMT_MAP entry: ${clean}    WARN
                CONTINUE
            END
            ${k}=    Strip String    ${parts}[0]
            ${v}=    Strip String    ${parts}[1]
            Set To Dictionary    ${map}    ${k}    ${v}
        END
    END
    Set Suite Variable    &{NODE_IPS}    &{map}

Resolve Node IP
    [Documentation]    Maps a data-model node ID to a reachable management IP.
    ...                Returns empty string when unmapped, so callers skip with
    ...                a clear reason rather than failing against a bad target.
    [Arguments]    ${node_id}
    ${ip}=    Evaluate    $NODE_IPS.get('${node_id}', '')
    RETURN    ${ip}

Select Fabric Node
    [Documentation]    Picks the first candidate node that has a management IP.
    ...                The anycast gateway is identical on every leaf where the
    ...                BD is deployed, so one reachable node is sufficient.
    [Arguments]    @{candidates}
    FOR    ${nid}    IN    @{candidates}
        ${ip}=    Resolve Node IP    ${nid}
        IF    '${ip}' != ''
            ${pair}=    Create List    ${nid}    ${ip}
            RETURN    ${pair}
        END
    END
    ${empty}=    Create List    ${EMPTY}    ${EMPTY}
    RETURN    ${empty}

Subnet Is In Scope
    [Documentation]    True when CHANGED_SUBNETS is empty (full sweep) or the
    ...                subnet appears in it. Compares the full CIDR and the bare
    ...                host address, so either extraction form from plan.json
    ...                works.
    [Arguments]    ${subnet_cidr}
    ${raw}=    Strip String    ${CHANGED_SUBNETS}
    IF    '${raw}' == ''
        RETURN    ${True}
    END
    ${host}=    Evaluate    '''${subnet_cidr}'''.split('/')[0]
    ${hit}=    Evaluate
    ...    any(t.strip() == '''${subnet_cidr}''' or t.strip().split('/')[0] == '''${host}''' for t in '''${raw}'''.split(',') if t.strip())
    RETURN    ${hit}

Open Switch Session
    [Documentation]    Opens an interactive shell on a leaf. invoke_shell()
    ...                requests a PTY, which is mandatory for iping.
    ...
    ...                Prefers public-key auth when SWITCH_KEYFILE is set. With
    ...                password auth the credential is passed as a keyword
    ...                argument, which Robot records unresolved (as
    ...                ${SWITCH_PASSWORD}) at default log level - but it WOULD be
    ...                written in clear text at DEBUG level. Never run this suite
    ...                with --loglevel DEBUG or nac-test --verbose.
    [Arguments]    ${switch_ip}
    Open Connection    ${switch_ip}
    ...    prompt=REGEXP:${SWITCH_PROMPT}
    ...    term_type=vt100    width=200    height=5000
    ...    timeout=${SSH_READ_TIMEOUT}
    IF    ${USE_KEY_AUTH}
        Login With Public Key    ${SWITCH_USER}    ${SWITCH_KEYFILE}
    ELSE
        Login    ${SWITCH_USER}    ${SWITCH_PASSWORD}
    END

Fabric Ping
    [Documentation]    Runs iping ON a leaf and returns the raw output.
    ...
    ...                Uses Write + Read Until Prompt, NOT Execute Command.
    ...                Verified on this fabric: the non-PTY exec channel returns
    ...                '\n\n\n\n\n' and exits 0, discarding everything. Exit
    ...                codes are unavailable in shell mode and would be
    ...                untrustworthy regardless - callers parse the text.
    ...
    ...                A failed session returns an SSH-ERROR string rather than
    ...                raising, so the caller can turn it into a specific
    ...                assertion message instead of an opaque library error.
    [Arguments]    ${switch_ip}    ${vrf}    ${dest}    ${source}=${EMPTY}
    ${cmd}=    Set Variable    iping -V ${vrf} -c ${PING_COUNT}
    IF    '${source}' != ''
        ${cmd}=    Set Variable    ${cmd} -S ${source}
    END
    ${cmd}=    Set Variable    ${cmd} ${dest}
    ${raw}=    Set Variable    ${EMPTY}
    TRY
        Open Switch Session    ${switch_ip}
        Write    ${cmd}
        ${status}    ${result}=    Run Keyword And Ignore Error
        ...    Read Until Prompt    strip_prompt=${True}
        IF    '${status}' == 'PASS'
            ${raw}=    Set Variable    ${result}
        ELSE
            Log    Prompt regexp ${SWITCH_PROMPT} did not match - falling back to a buffered read. Detail: ${result}    WARN
            ${fs}    ${fr}=    Run Keyword And Ignore Error    Read    delay=3s
            IF    '${fs}' == 'PASS'
                ${raw}=    Set Variable    ${fr}
            END
        END
    EXCEPT    *    type=GLOB    AS    ${err}
        Log    SSH session to ${switch_ip} failed: ${err}    WARN
        ${raw}=    Set Variable    SSH-ERROR: ${err}
    FINALLY
        Run Keyword And Ignore Error    Close Connection
    END
    # A PTY emits CRLF, and layered TTYs can double the CR. Normalise so the
    # statistics regexp sees plain newlines.
    ${out}=    Replace String    ${raw}    \r\n    \n
    ${out}=    Replace String    ${out}    \r    ${EMPTY}
    Log    ${switch_ip}: ${cmd}\n${out}
    RETURN    ${out}

Count Ping Replies
    [Documentation]    Parses iping output for the reply count.
    ...
    ...                Primary pattern is the statistics line, confirmed on this
    ...                fabric as:
    ...                  "3 packets transmitted, 3 packets received, 0.00% packet loss"
    ...                Two fallbacks cover alternative wordings and a truncated
    ...                run. Returns -1 when nothing parseable was produced.
    ...
    ...                In shell mode the captured text also contains the echoed
    ...                command, so every pattern is anchored to a form that
    ...                cannot appear in "iping -V ... -c 3 -S ... 8.8.8.8".
    [Arguments]    ${out}
    ${trimmed}=    Strip String    ${out}
    IF    '${trimmed}' == ''
        RETURN    ${-1}
    END
    @{a}=    Get Regexp Matches    ${out}    (\d+)\s+packets\s+received    1
    ${na}=    Get Length    ${a}
    IF    ${na} > 0
        ${v}=    Convert To Integer    ${a}[0]
        RETURN    ${v}
    END
    @{b}=    Get Regexp Matches    ${out}    (\d+)\s+received    1
    ${nb}=    Get Length    ${b}
    IF    ${nb} > 0
        ${v}=    Convert To Integer    ${b}[0]
        RETURN    ${v}
    END
    # icmp_seq= only ever appears on a genuine reply line.
    @{c}=    Get Regexp Matches    ${out}    bytes\s+from\s+\S+:\s+icmp_seq=
    ${nc}=    Get Length    ${c}
    IF    ${nc} > 0
        RETURN    ${nc}
    END
    RETURN    ${-1}

Fabric Ping Should Succeed
    [Documentation]    Asserts at least one ICMP reply by parsing output rather
    ...                than trusting an exit code. Distinguishes three outcomes:
    ...                the command was rejected, the harness captured nothing,
    ...                or the ping genuinely lost every packet. Only the last is
    ...                a fabric finding.
    [Arguments]    ${switch_ip}    ${vrf}    ${dest}    ${source}=${EMPTY}    ${label}=${EMPTY}
    ${out}=    Fabric Ping    ${switch_ip}    ${vrf}    ${dest}    ${source}
    ${lower}=    Convert To Lower Case    ${out}
    FOR    ${bad}    IN    ssh-error    authentication    permission denied
    ...    invalid    unknown vrf    no such vrf    cannot find    bad source
    ...    % invalid    syntax error    no route to host
        IF    '${bad}' in '''${lower}'''
            Run Keyword And Continue On Failure    Fail
            ...    ${label}: iping did not run on ${switch_ip} ("${bad}") - check that VRF ${vrf} exists, that source ${source} is deployed on this leaf, and that the SSH credential is valid. Output: ${out}
            RETURN
        END
    END
    ${received}=    Count Ping Replies    ${out}
    IF    ${received} < 0
        Run Keyword And Continue On Failure    Fail
        ...    ${label}: no parseable iping output from ${switch_ip}. The prompt regexp may not match this leaf, or the session closed early. Output: ${out}
    ELSE IF    ${received} == 0
        Run Keyword And Continue On Failure    Fail
        ...    ${label}: total loss from node ${switch_ip} in VRF ${vrf} to ${dest} (source=${source})
    ELSE
        Log    ${label}: ${received}/${PING_COUNT} replies from ${switch_ip} -> ${dest}
    END

TCP Port Should Be Open
    [Documentation]    Capability-safe reachability check - no ICMP, so it works
    ...                even where NET_RAW is dropped. Returns connect_ex rc;
    ...                0 means open.
    [Arguments]    ${host}    ${port}    ${timeout}=${TCP_TIMEOUT}
    ${sock}=    Evaluate    __import__('socket').socket()    modules=socket
    ${addr}=    Evaluate    ('${host}', ${port})
    TRY
        Call Method    ${sock}    settimeout    ${timeout}
        ${rc}=    Call Method    ${sock}    connect_ex    ${addr}
    FINALLY
        Call Method    ${sock}    close
    END
    RETURN    ${rc}

Resolver Should Answer
    [Documentation]    Queries one resolver directly and returns the first answer,
    ...                or empty string. The '=' in dig's +opt=value MUST be
    ...                escaped - Robot otherwise reads '+time=3' as a named
    ...                argument called '+time'.
    [Arguments]    ${server}    ${name}
    ${result}=    Run Process    dig    @${server}    ${name}    A    +short
    ...    +time\=${DIG_TIMEOUT}    +tries\=1
    ...    stdout=PIPE    stderr=PIPE    timeout=15s    on_timeout=terminate
    Log    ${server} -> rc=${result.rc} ${result.stdout}${result.stderr}
    IF    ${result.rc} != 0
        RETURN    ${EMPTY}
    END
    @{lines}=    Split To Lines    ${result.stdout.strip()}
    ${count}=    Get Length    ${lines}
    IF    ${count} == 0
        RETURN    ${EMPTY}
    END
    RETURN    ${lines}[0]

*** Test Cases ***
{#- ══════════════════════════════════════════════════════════════════ -#}
{#- Build two node maps per tenant, then intersect them per BD:        -#}
{#-   l3out_nodes     : leaves carrying an L3Out (have the ext route)   -#}
{#-   bd_deploy_nodes : leaves where the BD is deployed via static      -#}
{#-                     ports (so the pervasive SVI exists there)      -#}
{#- A leaf must be in BOTH to source a ping from the gateway toward an  -#}
{#- external destination: -S needs the local SVI, and the destination   -#}
{#- needs the L3Out.                                                   -#}
{#- ══════════════════════════════════════════════════════════════════ -#}
{% for tenant in apic.tenants | default([]) %}

{%- set l3out_nodes = {} %}
{%- for l3out in tenant.l3outs | default([]) %}
{%-   set ns = [] %}
{%-   for np in l3out.node_profiles | default([]) %}
{%-     for node in np.nodes | default([]) %}
{%-       if node.node_id is defined and node.node_id not in ns %}
{%-         set _ = ns.append(node.node_id) %}
{%-       endif %}
{%-     endfor %}
{%-   endfor %}
{%-   set _ = l3out_nodes.update({l3out.name: ns}) %}
{%- endfor %}

{%- set bd_deploy_nodes = {} %}
{%- for ap in tenant.application_profiles | default([]) %}
{%-   for epg in ap.endpoint_groups | default([]) %}
{%-     if epg.bridge_domain is defined %}
{%-       set ns = bd_deploy_nodes.get(epg.bridge_domain, []) %}
{%-       for sp in epg.static_ports | default([]) %}
{%-         if sp.node_id is defined and sp.node_id not in ns %}
{%-           set _ = ns.append(sp.node_id) %}
{%-         endif %}
{%-         if sp.node2_id is defined and sp.node2_id not in ns %}
{%-           set _ = ns.append(sp.node2_id) %}
{%-         endif %}
{%-       endfor %}
{%-       set _ = bd_deploy_nodes.update({epg.bridge_domain: ns}) %}
{%-     endif %}
{%-   endfor %}
{%- endfor %}

{%- for bd in tenant.bridge_domains | default([]) %}
{%- if bd.vrf is defined %}

{%-   set border_nodes = [] %}
{%-   for lo in bd.l3outs | default([]) %}
{%-     for n in l3out_nodes.get(lo, []) %}
{%-       if n not in border_nodes %}{% set _ = border_nodes.append(n) %}{% endif %}
{%-     endfor %}
{%-   endfor %}

{%-   set deploy_nodes = bd_deploy_nodes.get(bd.name, []) %}

{#-   Preferred: leaves that are both border and BD-deployed. -#}
{%-   set candidates = [] %}
{%-   for n in deploy_nodes %}
{%-     if n in border_nodes and n not in candidates %}
{%-       set _ = candidates.append(n) %}
{%-     endif %}
{%-   endfor %}
{#-   Fallbacks in order of decreasing confidence. A deploy-only leaf can  -#}
{#-   source the ping but may lack the external route; a border-only leaf  -#}
{#-   has the route but may not host the SVI.                              -#}
{%-   if candidates | length == 0 %}{% set candidates = deploy_nodes %}{% endif %}
{%-   if candidates | length == 0 %}{% set candidates = border_nodes %}{% endif %}

{%-   for subnet in bd.subnets | default([]) %}
{%-     if subnet.ip is defined and subnet.public | default(false) and candidates | length > 0 %}
{%-       set gw = subnet.ip.split('/')[0] %}

Fabric Egress From {{ tenant.name }} {{ bd.name }} Gateway {{ gw }}
    [Documentation]    iping on a border leaf, sourced from the BD anycast
    ...                gateway {{ gw }} in VRF {{ tenant.name }}:{{ bd.vrf }},
    ...                towards ${FABRIC_EXT_TARGET}.
    ...
    ...                A pass proves the pervasive SVI is deployed, unicast
    ...                routing is on, {{ subnet.ip }} is advertised out
    ...                {{ bd.l3outs | default([]) | join(', ') }}, the contract
    ...                permits ICMP, and return traffic lands.
    ...
    ...                Candidate leaves {{ candidates | join(', ') }} - the
    ...                intersection of L3Out border nodes and leaves where this
    ...                BD is deployed via static ports.
    [Tags]    fabric-icmp    d2d    subnet-egress
    ${in_scope}=    Subnet Is In Scope    {{ subnet.ip }}
    Skip If    not ${in_scope}
    ...    {{ subnet.ip }} is not part of this change (CHANGED_SUBNETS=${CHANGED_SUBNETS})
    Skip If    not ${SSH_CONFIGURED}
    ...    NODE_MGMT_MAP / SWITCH_USER / credential not configured - no fabric SSH target
    @{cands}=    Create List    {{ candidates | join('    ') }}
    ${node}=    Select Fabric Node    @{cands}
    Skip If    '${node}[1]' == ''
    ...    None of the candidate nodes {{ candidates | join(', ') }} has an entry in NODE_MGMT_MAP
    Fabric Ping Should Succeed    ${node}[1]
    ...    {{ tenant.name }}:{{ bd.vrf }}
    ...    ${FABRIC_EXT_TARGET}
    ...    {{ gw }}
    ...    label=egress from {{ bd.name }} gw {{ gw }} (node ${node}[0])

Fabric Reach DNS From {{ tenant.name }} {{ bd.name }} Gateway {{ gw }}
    [Documentation]    iping from the BD gateway to each shared-services
    ...                resolver, inside {{ tenant.name }}:{{ bd.vrf }}. This is
    ...                the check that most often catches a subnet added without
    ...                the matching contract or route leak.
    [Tags]    fabric-icmp    d2d    shared-services
    ${in_scope}=    Subnet Is In Scope    {{ subnet.ip }}
    Skip If    not ${in_scope}
    ...    {{ subnet.ip }} is not part of this change (CHANGED_SUBNETS=${CHANGED_SUBNETS})
    Skip If    not ${SSH_CONFIGURED}
    ...    NODE_MGMT_MAP / SWITCH_USER / credential not configured - no fabric SSH target
    @{cands}=    Create List    {{ candidates | join('    ') }}
    ${node}=    Select Fabric Node    @{cands}
    Skip If    '${node}[1]' == ''
    ...    None of the candidate nodes {{ candidates | join(', ') }} has an entry in NODE_MGMT_MAP
    FOR    ${srv}    IN    @{DNS_SERVERS}
        Fabric Ping Should Succeed    ${node}[1]
        ...    {{ tenant.name }}:{{ bd.vrf }}
        ...    ${srv}
        ...    {{ gw }}
        ...    label=dns ${srv} from {{ bd.name }} gw {{ gw }}
    END

Runner Ping Gateway {{ gw }} In {{ tenant.name }} BD {{ bd.name }}
    [Documentation]    ICMP from the CI container to the BD anycast gateway.
    ...
    ...                Valid because {{ subnet.ip }} is public:true behind
    ...                {{ bd.l3outs | default([]) | join(', ') }}, so the gateway
    ...                is reachable from the cluster. This is the north-south
    ...                counterpart to the fabric-sourced test above: together
    ...                they prove both directions of the L3Out path.
    ...
    ...                A failure here while the fabric-sourced test passes points
    ...                at external route advertisement or the contract on the
    ...                external EPG, not at the BD itself.
    [Tags]    fabric-ping    l3out-north-south    icmp
    ${in_scope}=    Subnet Is In Scope    {{ subnet.ip }}
    Skip If    not ${in_scope}
    ...    {{ subnet.ip }} is not part of this change (CHANGED_SUBNETS=${CHANGED_SUBNETS})
    Skip If    not ${GATEWAY_PING_ENABLED}
    ...    GATEWAY_PING_ENABLED is False for this environment
    Skip If    not ${ICMP_AVAILABLE}    ${ICMP_REASON}
    ${result}=    Run Process    ping    -c    3    -W    2    {{ gw }}
    ...    stdout=PIPE    stderr=PIPE    timeout=20s    on_timeout=terminate
    Log    ${result.stdout}${result.stderr}
    IF    ${result.rc} != 0
        Run Keyword And Continue On Failure    Fail
        ...    Gateway {{ gw }} ({{ bd.name }}, {{ subnet.ip }}) is not reachable from the runner via the L3Out (rc=${result.rc}): ${result.stdout}
    END

{%-     endif %}
{%-   endfor %}
{%- endif %}
{%- endfor %}
{%- endfor %}

# ─── management-VRF reachability per node (baseline, not change-scoped) ───
Fabric Nodes Reach DNS In Management VRF
    [Documentation]    iping from each leaf's in-band management VRF to the
    ...                resolvers. Tagged baseline: this reflects pre-existing
    ...                fabric management state, not the subnet being added.
    ...
    ...                MGMT_VRF defaults to mgmt:inb. Out-of-band lives in a
    ...                separate namespace and may need plain ping rather than
    ...                iping - confirm with 'show vrf' on a leaf.
    [Tags]    baseline    fabric-icmp    d2d
    Skip If    not ${SSH_CONFIGURED}
    ...    NODE_MGMT_MAP / SWITCH_USER / credential not configured - no fabric SSH target
    @{node_ids}=    Get Dictionary Keys    ${NODE_IPS}
    FOR    ${nid}    IN    @{node_ids}
        ${ip}=    Resolve Node IP    ${nid}
        FOR    ${srv}    IN    @{DNS_SERVERS}
            Fabric Ping Should Succeed    ${ip}    ${MGMT_VRF}    ${srv}
            ...    label=node ${nid} mgmt -> dns ${srv}
        END
    END

# ══════════════════════════════════════════════════════════════════
# RUNNER-SIDE shared services and egress
# ══════════════════════════════════════════════════════════════════
Verify DHCP Server Is Reachable
    [Documentation]    TCP-based reachability so it works without NET_RAW.
    ...                Port 53 is used because the DHCP relay provider
    ...                (dhcp.emea-se.dcloud.cisco.com) also serves DNS here.
    ${rc}=    TCP Port Should Be Open    ${DHCP_SERVER}    53
    IF    ${rc} != 0
        Run Keyword And Continue On Failure    Fail
        ...    DHCP/DNS server ${DHCP_SERVER} is not reachable on tcp/53 (connect_ex rc=${rc})
    END

Verify DNS Servers Answer Queries
    [Documentation]    Authoritative resolver check - a real query, not a TCP
    ...                handshake. DNS is UDP-first, so tcp/53 being closed does
    ...                not imply an unhealthy resolver.
    Skip If    not ${DIG_AVAILABLE}    dig is not installed in the runner image
    ${silent}=    Create List
    FOR    ${srv}    IN    @{DNS_SERVERS}
        ${ans}=    Resolver Should Answer    ${srv}    ${DNS_PROBE_NAME}
        IF    '${ans}' == ''
            Append To List    ${silent}    ${srv}
        END
    END
    ${n_silent}=    Get Length    ${silent}
    IF    ${n_silent} > 0
        Run Keyword And Continue On Failure    Fail
        ...    Resolvers returned no A record for ${DNS_PROBE_NAME}: ${silent}
    END

Verify DNS Servers Agree Or Both Fail
    [Documentation]    A resolver answering while its peer does not is a real
    ...                signal and fails. Differing ADDRESSES for the same name
    ...                are NOT a failure - CDN and round-robin records
    ...                legitimately differ per resolver - so divergence is
    ...                logged as a warning.
    Skip If    not ${DIG_AVAILABLE}    dig is not installed in the runner image
    ${answers}=    Create List
    ${silent}=     Create List
    FOR    ${srv}    IN    @{DNS_SERVERS}
        ${ans}=    Resolver Should Answer    ${srv}    ${DNS_PROBE_NAME}
        IF    '${ans}' == ''
            Append To List    ${silent}    ${srv}
        ELSE
            Append To List    ${answers}    ${ans}
        END
    END
    Log    answered=${answers} silent=${silent}
    ${n_ans}=       Get Length    ${answers}
    ${n_silent}=    Get Length    ${silent}
    IF    ${n_ans} > 0 and ${n_silent} > 0
        Run Keyword And Continue On Failure    Fail
        ...    Inconsistent resolver behaviour for ${DNS_PROBE_NAME}: ${silent} returned nothing while others answered
    ELSE IF    ${n_ans} == 0
        Run Keyword And Continue On Failure    Fail
        ...    No resolver returned an A record for ${DNS_PROBE_NAME}
    ELSE
        ${unique}=    Remove Duplicates    ${answers}
        ${n_uniq}=    Get Length    ${unique}
        IF    ${n_uniq} > 1
            Log    Resolvers returned different addresses (${unique}) - expected for CDN records    WARN
        END
    END

Verify Outbound HTTPS To External Hosts
    [Documentation]    curl needs no elevated capability, so this is the reliable
    ...                internet check in a container. '-o' MUST have a real path:
    ...                passing ${EMPTY} makes curl reject the command line with
    ...                rc=2 (CURLE_FAILED_INIT, "option -o: is badly used here").
    ...                Tagged baseline because a failure here usually means
    ...                upstream egress or proxy, not this change.
    [Tags]    baseline
    FOR    ${host}    IN    @{EXTERNAL_HOSTS}
        ${result}=    Run Process    curl    -f    -s    -S
        ...    -o    /dev/null
        ...    --max-time    ${CURL_TIMEOUT}    https://${host}
        ...    stdout=PIPE    stderr=PIPE    timeout=20s    on_timeout=terminate
        Log    ${host} rc=${result.rc} ${result.stdout}${result.stderr}
        IF    ${result.rc} != 0
            Run Keyword And Continue On Failure    Fail
            ...    HTTPS to ${host} failed (curl rc=${result.rc}): ${result.stderr}
        END
    END

Verify Outbound HTTPS To Internal Endpoint
    [Documentation]    Skipped unless INTERNAL_HTTPS_HOST is set. Prefer this
    ...                over the external hosts test - it reflects fabric egress
    ...                rather than whether google.com happens to be reachable
    ...                from a CI container.
    [Tags]    baseline
    Skip If    '${INTERNAL_HTTPS_HOST}' == ''
    ...    INTERNAL_HTTPS_HOST is not set - no internal HTTPS target configured
    ${result}=    Run Process    curl    -f    -s    -S    -k
    ...    -o    /dev/null
    ...    --max-time    ${CURL_TIMEOUT}    https://${INTERNAL_HTTPS_HOST}
    ...    stdout=PIPE    stderr=PIPE    timeout=20s    on_timeout=terminate
    Log    ${INTERNAL_HTTPS_HOST} rc=${result.rc} ${result.stderr}
    IF    ${result.rc} != 0
        Run Keyword And Continue On Failure    Fail
        ...    HTTPS to ${INTERNAL_HTTPS_HOST} failed (curl rc=${result.rc}): ${result.stderr}
    END

Verify External Name Resolution Via System Resolver
    [Documentation]    Uses the runner's configured resolver rather than a
    ...                specific server - proves end-to-end name resolution.
    [Tags]    baseline
    FOR    ${host}    IN    @{EXTERNAL_HOSTS}
        ${status}    ${addr}=    Run Keyword And Ignore Error
        ...    Evaluate    __import__('socket').gethostbyname('${host}')    modules=socket
        Log    ${host} -> ${status} ${addr}
        IF    '${status}' != 'PASS'
            Run Keyword And Continue On Failure    Fail
            ...    Could not resolve ${host} via the system resolver: ${addr}
        END
    END