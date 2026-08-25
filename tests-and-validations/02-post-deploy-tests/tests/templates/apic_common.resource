*** Settings ***
Library   pabot.PabotLib
Library   RequestsLibrary
Library   JSONLibrary
Library   Collections
Library   OperatingSystem
Library   DateTime
Library   ./JMESPath.py

*** Variables ***
${login_json}   {"aaaUser" : {"attributes" : {"name" : "%{ACI_USERNAME}", "pwd" : "%{ACI_PASSWORD}"}}}
${state_path}   tests/state/


*** Keywords ***
Check APIC Token Timestamp
    ${current_time}=   Get Current Date   result_format=epoch
    ${token_timestamp}=   Get Parallel Value For Key   apic_token_timestamp
    ${expires}=   Evaluate   (${token_timestamp} - ${current_time}) <= 60
    RETURN   ${expires}

Verify APIC Token
    ${token_expires}=   Check APIC Token Timestamp
    IF   ${token_expires}
        Acquire Lock   apic_token_refresh
        TRY
            ${token_expires}=   Check APIC Token Timestamp
            IF   ${token_expires}
                Get APIC Token
            END
        EXCEPT
            Fatal Error   APIC Token Refresh Failed
        FINALLY
            Release Lock   apic_token_refresh
        END
    END

Get APIC Token
    Create Session   login   %{ACI_URL}
    ${log_level}=   Set Log Level   NONE
    Evaluate    __import__('urllib3').disable_warnings()
    ${response}=   Wait Until Keyword Succeeds   6x   10s   POST On Session   login   /api/aaaLogin.json   data=${login_json}
    Set Log Level   ${log_level}
    ${r_token}=   Get Value From Json   ${response.json()}   $..token
    Set Parallel Value For Key   apic_token   ${r_token[0]}
    ${token_creation_time}=   Get Current Date   result_format=epoch
    ${token_refresh_timeout}=   Get Value From Json   ${response.json()}   $..refreshTimeoutSeconds
    ${token_timestamp}=   Evaluate   ${token_creation_time} + ${token_refresh_timeout[0]}
    Set Parallel Value For Key   apic_token_timestamp   ${token_timestamp}

Login APIC
    Run Only Once    Get APIC Token
    Verify APIC Token
    ${apic_token}=    Get Parallel Value For Key    apic_token
    Create Session    apic    %{ACI_URL}    headers={"Cookie": "APIC-cookie=${apic_token}"}
    Set Global Variable    ${STATE_PATH}    ${state_path}
    Evaluate    __import__('urllib3').disable_warnings()

Should Be Equal Value Json String
    [Arguments]    ${json}    ${json_path}   ${value}=${EMPTY}
    ${r_value}=   Get Value From Json   ${json}   ${json_path}
    Run Keyword If   "${value}" != "${EMPTY}"   Should Be Equal As Strings   ${r_value}[0]   ${value}

Should Be Equal Value Json List
    [Arguments]    ${json}    ${json_path}   ${value}=${None}
    ${r_value}=   Get Value From Json   ${json}   ${json_path}
    Run Keyword If   "${value}" != "${None}"   Lists Should Be Equal   ${r_value}   ${value}   ignore_order=True

Should Be Equal JMESPath Json
    [Arguments]    ${json}    ${jmespath}   ${value}=${EMPTY}
    ${r_value}=   Json Search String   ${json}   ${jmespath}
    Run Keyword If   $value   Should Be Equal As Strings   ${r_value}   ${value}

Get JMESPath Value
    [Arguments]    ${json}    ${jmespath}
    ${r_value}=   Json Search String   ${json}   ${jmespath}
    RETURN   ${r_value}

Should Be Equal JMESPath Json List
    [Arguments]    ${json}    ${jmespath}   ${value}=${None}
    ${r_value}=   Json Search List   ${json}   ${jmespath}
    Run Keyword If   $value is not None    Lists Should Be Equal   ${r_value}   ${value}   ignore_order=True

Should Not Be Empty JMESPath Json
    [Arguments]    ${json}    ${jmespath}
    ${r_value}=   Json Search List   ${json}   ${jmespath}
    Should Not Be Empty   ${r_value}   msg=JMESPath query returned empty result: ${jmespath}
