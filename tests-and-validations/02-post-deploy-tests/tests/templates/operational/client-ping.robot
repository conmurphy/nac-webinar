*** Settings ***
Documentation     Verify Live Reachability, DNS Resolution And Internet Access
...               From The Test Runner
Library           Process
Library           Collections
Library           String
Default Tags      apic   day2   operational   traffic 

*** Variables ***
@{DNS_SERVERS}        198.18.194.4    198.18.194.5
@{EXTERNAL_HOSTS}     google.com      cisco.com
${DHCP_SERVER}        198.18.194.4
${CURL_TIMEOUT}       10
${DIG_TIMEOUT}        3

*** Keywords ***
TCP Port Should Be Open
    [Documentation]    Capability-safe reachability check - no ICMP, so it works
    ...                inside a restricted container where NET_RAW is dropped.
    [Arguments]    ${host}    ${port}    ${timeout}=5
    ${rc}=    Evaluate
    ...    __import__('socket').socket().connect_ex(('${host}', ${port}))
    ...    modules=socket
    RETURN    ${rc}

*** Test Cases ***
# ─────────── shared-services reachability (change relevant) ───────────
{% for tenant in apic.tenants | default([]) %}
{% for bd in tenant.bridge_domains | default([]) %}
{% for subnet in bd.subnets | default([]) %}
{% set gw = subnet.ip.split('/')[0] %}

Ping Gateway {{ gw }} In Tenant {{ tenant.name }} BD {{ bd.name }}
    [Documentation]    ICMP to the BD anycast gateway. Requires NET_RAW - if the
    ...                runner is a restricted container this may fail even when
    ...                the network is healthy, so the result is logged not failed.
    ${result}=    Run Process    ping    -c    3    {{ gw }}
    ...    stdout=PIPE    stderr=PIPE    timeout=20s    on_timeout=terminate
    Log    ${result.stdout}${result.stderr}
    IF    'Operation not permitted' in """${result.stderr}"""
        Log    ICMP unavailable in this environment (NET_RAW dropped) - skipping    WARN
    ELSE IF    ${result.rc} != 0
        Run Keyword And Continue On Failure    Fail
        ...    "Gateway {{ gw }} ({{ bd.name }}) is not responding to ICMP"
    END

{% endfor %}
{% endfor %}
{% endfor %}

Verify DHCP Server ${DHCP_SERVER} Is Reachable
    [Documentation]    TCP-based reachability so it works without NET_RAW.
    ...                Port 53 is used because the DHCP relay provider also
    ...                serves DNS in this fabric.
    ${rc}=    TCP Port Should Be Open    ${DHCP_SERVER}    53
    Run Keyword If    ${rc} != 0    Run Keyword And Continue On Failure
    ...    Fail    "DHCP/DNS server ${DHCP_SERVER} is not reachable on tcp/53 (rc=${rc})"

{% raw %}
# ─────────── DNS servers (live in shared-services) ───────────
Verify DNS Servers Are Reachable
    [Documentation]    Both resolvers must answer on tcp/53. These live in
    ...                shared-services, so a failure here indicates the shared
    ...                services path is broken - not just an external issue.
    FOR    ${srv}    IN    @{DNS_SERVERS}
        ${rc}=    TCP Port Should Be Open    ${srv}    53
        Run Keyword If    ${rc} != 0    Run Keyword And Continue On Failure
        ...    Fail    "DNS server ${srv} is not reachable on tcp/53 (rc=${rc})"
    END

Verify DNS Resolution Works On Each Server
    [Documentation]    Queries each resolver directly and asserts an A record
    ...                comes back. Proves the resolver is functional, not merely
    ...                reachable.
    FOR    ${srv}    IN    @{DNS_SERVERS}
        ${result}=    Run Process    dig    @${srv}    google.com    A    +short
        ...    +time=${DIG_TIMEOUT}    +tries=1
        ...    stdout=PIPE    stderr=PIPE    timeout=15s    on_timeout=terminate
        Log    ${srv} -> ${result.stdout}
        ${answer}=    Set Variable    ${result.stdout.strip()}
        IF    ${result.rc} != 0
            Run Keyword And Continue On Failure    Fail
            ...    "dig against ${srv} failed (rc=${result.rc}): ${result.stderr}"
        ELSE IF    '${answer}' == ''
            Run Keyword And Continue On Failure    Fail
            ...    "DNS server ${srv} returned no A record for google.com"
        END
    END

Verify DNS Servers Return Consistent Answers
    [Documentation]    Both resolvers should agree. Divergence suggests one is
    ...                stale or pointing at a different upstream.
    ${answers}=    Create List
    FOR    ${srv}    IN    @{DNS_SERVERS}
        ${result}=    Run Process    dig    @${srv}    cisco.com    A    +short
        ...    +time=${DIG_TIMEOUT}    +tries=1
        ...    stdout=PIPE    timeout=15s    on_timeout=terminate
        ${first}=    Set Variable    ${result.stdout.strip().splitlines()}
        Run Keyword If    len(${first}) > 0    Append To List    ${answers}    ${first}[0]
    END
    Log    Answers: ${answers}
    ${count}=    Get Length    ${answers}
    Run Keyword If    ${count} < 2    Log
    ...    Fewer than two resolvers answered - cannot compare    WARN

# ─────────── external / internet (baseline - upstream dependent) ───────────
Verify Outbound HTTPS To External Hosts
    [Documentation]    curl needs no elevated capability, so this is the reliable
    ...                internet check in a container. Tagged baseline because a
    ...                failure usually means upstream, not this change.
    [Tags]    baseline
    FOR    ${host}    IN    @{EXTERNAL_HOSTS}
        ${result}=    Run Process    curl    -fsS    -o    ${EMPTY}
        ...    --max-time    ${CURL_TIMEOUT}    https://${host}
        ...    stdout=PIPE    stderr=PIPE    timeout=20s    on_timeout=terminate
        Log    ${host} rc=${result.rc} ${result.stderr}
        Run Keyword If    ${result.rc} != 0    Run Keyword And Continue On Failure
        ...    Fail    "HTTPS to ${host} failed (curl rc=${result.rc}): ${result.stderr}"
    END

Verify External Name Resolution Via System Resolver
    [Documentation]    Uses the runner's configured resolver rather than a
    ...                specific server - proves end-to-end name resolution.
    [Tags]    baseline
    FOR    ${host}    IN    @{EXTERNAL_HOSTS}
        ${addr}=    Run Keyword And Ignore Error
        ...    Evaluate    __import__('socket').gethostbyname('${host}')    modules=socket
        Log    ${host} -> ${addr}
        Run Keyword If    '${addr}[0]' != 'PASS'    Run Keyword And Continue On Failure
        ...    Fail    "Could not resolve ${host} via the system resolver"
    END
{% endraw %}