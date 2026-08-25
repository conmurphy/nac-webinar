*** Settings ***
Documentation     Verify Fabric Hardware And Environmental State
Suite Setup       Login APIC
Default Tags      apic   day2   operational   hardware   baseline
Resource          ../apic_common.resource

*** Test Cases ***
Verify All Fabric Nodes Are Active
    ${r}=    GET On Session    apic
    ...    /api/node/class/fabricNode.json
    ...    params=query-target-filter=ne(fabricNode.fabricSt,"active")
    Set Suite Variable    $r    ${r.json()}
    ${count}=    Get Value From Json    ${r}    $.totalCount
    Run Keyword If    ${count}[0] > 0    Run Keyword And Continue On Failure
    ...    Fail    "${count}[0] fabric node(s) not in active state"

Verify APIC Cluster Is Fully Fit
    ${r}=    GET On Session    apic    /api/node/class/infraWiNode.json
    Set Suite Variable    $r    ${r.json()}
    @{health}=    Get Value From Json    ${r}    $..infraWiNode.attributes.health
    FOR    ${h}    IN    @{health}
        Run Keyword If    "${h}" != "fully-fit"    Run Keyword And Continue On Failure
        ...    Fail    "APIC cluster member health is ${h}, expected fully-fit"
    END

Verify All Power Supplies Are Operational
    ${r}=    GET On Session    apic
    ...    /api/node/class/eqptPsu.json
    ...    params=query-target-filter=ne(eqptPsu.operSt,"on")
    Set Suite Variable    $r    ${r.json()}
    ${count}=    Get Value From Json    ${r}    $.totalCount
    Run Keyword If    ${count}[0] > 0    Run Keyword And Continue On Failure
    ...    Fail    "${count}[0] power supply/supplies not in 'on' state"

Verify All Fan Trays Are Operational
    ${r}=    GET On Session    apic
    ...    /api/node/class/eqptFt.json
    ...    params=query-target-filter=ne(eqptFt.operSt,"ok")
    Set Suite Variable    $r    ${r.json()}
    ${count}=    Get Value From Json    ${r}    $.totalCount
    Run Keyword If    ${count}[0] > 0    Run Keyword And Continue On Failure
    ...    Fail    "${count}[0] fan tray(s) not in 'ok' state"

Verify No Critical Fabric Faults
    ${r}=    GET On Session    apic
    ...    /api/node/class/faultInst.json
    ...    params=query-target-filter=eq(faultInst.severity,"critical")
    Set Suite Variable    $r    ${r.json()}
    ${count}=    Get Value From Json    ${r}    $.totalCount
    Run Keyword If    ${count}[0] > 0    Run Keyword And Continue On Failure
    ...    Fail    "${count}[0] critical fault(s) present in the fabric"