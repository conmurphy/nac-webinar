*** Settings ***
Documentation     Verify Live Reachability, DNS Resolution And Internet Access
...               From The Test Runner
Library           Process
Library           Collections
Suite Setup       Probe Runner Capabilities
Test Tags         apic    day2    operational    traffic

*** Variables ***
@{DNS_SERVERS}            198.18.194.4    198.18.194.5
@{EXTERNAL_HOSTS}         google.com      cisco.com
${DHCP_SERVER}            198.18.194.4
${CURL_TIMEOUT}           10
${DIG_TIMEOUT}            3
${TCP_TIMEOUT}            5
# Name used to test that each resolver is functional. Point this at an
# INTERNAL record so the test does not depend on upstream internet.
${DNS_PROBE_NAME}         google.com
# Internal HTTPS endpoint. Prefer this over EXTERNAL_HOSTS for anything
# that should reflect fabric health rather than upstream availability.
${INTERNAL_HTTPS_HOST}    ${EMPTY}
# Populated by Suite Setup.
${ICMP_AVAILABLE}         ${False}
${ICMP_REASON}            ICMP capability not probed

*** Keywords ***
Probe Runner Capabilities
    [Documentation]    Establishes once, at suite level, whether this container
    ...                can execute ping at all. A binary carrying cap_net_raw+ep
    ...                inside a pod whose bounding set lacks NET_RAW makes execve
    ...                fail with EPERM, so Run Process RAISES rather than
    ...                returning a result. That cannot be caught by inspecting
    ...                stderr - it has to be caught around the call.
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

TCP Port Should Be Open
    [Documentation]    Capability-safe reachability check - no ICMP, so it works
    ...                inside a restricted container where NET_RAW is dropped.
    ...                Returns connect_ex rc; 0 means open.
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
# ─────────── BD gateway ICMP (informational - needs NET_RAW) ───────────
{% for tenant in apic.tenants | default([]) %}
{% for bd in tenant.bridge_domains | default([]) %}
{% for subnet in bd.subnets | default([]) %}
{% set gw = subnet.ip.split('/')[0] %}

Ping Gateway {{ gw }} In Tenant {{ tenant.name }} BD {{ bd.name }}
    [Documentation]    ICMP to the BD anycast gateway. Requires NET_RAW, which
    ...                restricted containers do not have, so this is SKIPPED
    ...                rather than failed when the capability is missing.
    ...                Tagged fabric-ping AND baseline: fabric-ping keeps it out
    ...                of the gating run, baseline keeps it in the informational
    ...                run. Without both tags it would run in neither.
    [Tags]    fabric-ping    baseline    icmp
    Skip If    not ${ICMP_AVAILABLE}    ${ICMP_REASON}
    ${result}=    Run Process    ping    -c    3    -W    2    {{ gw }}
    ...    stdout=PIPE    stderr=PIPE    timeout=20s    on_timeout=terminate
    Log    ${result.stdout}${result.stderr}
    IF    ${result.rc} != 0
        Run Keyword And Continue On Failure    Fail
        ...    Gateway {{ gw }} ({{ bd.name }}) is not responding to ICMP (rc=${result.rc})
    END

{% endfor %}
{% endfor %}
{% endfor %}

{% raw %}
# ─────────── shared-services reachability (change relevant) ───────────
Verify DHCP Server Is Reachable
    [Documentation]    TCP-based reachability so it works without NET_RAW.
    ...                Port 53 is used because the DHCP relay provider also
    ...                serves DNS in this fabric.
    ${rc}=    TCP Port Should Be Open    ${DHCP_SERVER}    53
    IF    ${rc} != 0
        Run Keyword And Continue On Failure    Fail
        ...    DHCP/DNS server ${DHCP_SERVER} is not reachable on tcp/53 (connect_ex rc=${rc})
    END

Verify DNS Servers Are Reachable
    [Documentation]    Both resolvers must answer on tcp/53. These live in
    ...                shared-services, so a failure here indicates the shared
    ...                services path is broken - not just an external issue.
    FOR    ${srv}    IN    @{DNS_SERVERS}
        ${rc}=    TCP Port Should Be Open    ${srv}    53
        IF    ${rc} != 0
            Run Keyword And Continue On Failure    Fail
            ...    DNS server ${srv} is not reachable on tcp/53 (connect_ex rc=${rc})
        END
    END

Verify DNS Servers Agree Or Both Fail
    [Documentation]    A resolver answering while its peer does not is a real
    ...                signal and fails. Differing ADDRESSES for the same name
    ...                are NOT a failure - CDN and round-robin records legitimately
    ...                differ per resolver - so divergence is logged as a warning.
    ...                For a hard equality assertion, point DNS_PROBE_NAME at an
    ...                internal record with a single static A.
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

# ─────────── external / internet (baseline - upstream dependent) ───────────
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
{% endraw %}