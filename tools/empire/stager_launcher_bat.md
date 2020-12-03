# Empire Stager

## Goal 
| Simulation # | Stager Option  |
| ------------ | -------------- |
| 1            | launcher_bat   |


## Technical Context
### Simulation 1
This attack example maybe used by attacker in a physical way, such as rubber ducky

#### Payload Generation
```bash
(Empire) > usestager windows/launcher_bat
```

#### Attack Begin

1. Generate the .bat payload
2. User click the .bat file, in reality it can be executed by autorun.inf

##### Raw Sysmon Event
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-03T00:26:42.364910700Z'/><EventRecordID>14242</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-03 00:26:42.364</Data><Data Name='ProcessGuid'>{84453EAB-30C2-5FC8-B4AA-080200000000}</Data><Data Name='ProcessId'>3316</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='FileVersion'>6.1.7600.16385 (win7_rtm.090713-1255)</Data><Data Name='Description'>Windows PowerShell</Data><Data Name='Product'>Microsoft® Windows® Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  -nol -nop -ep bypass "[IO.File]::ReadAllText('C:\Users\IEuser\Desktop\launcher.bat')|iex" </Data><Data Name='CurrentDirectory'>C:\Users\IEuser\Desktop\</Data><Data Name='User'>WIN-40TITGP9BI7\IEuser</Data><Data Name='LogonGuid'>{84453EAB-6BA3-5FC6-A0CC-080000000000}</Data><Data Name='LogonId'>0x8cca0</Data><Data Name='TerminalSessionId'>2</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=852D67A27E454BD389FA7F02A8CBE23F,SHA256=A8FDBA9DF15E41B6F5C69C79F66A26A9D48E174F9E7018A371600B866867DAB8,IMPHASH=F2C0E8A5BD10DBC167455484050CD683</Data><Data Name='ParentProcessGuid'>{84453EAB-30C2-5FC8-00A8-080200000000}</Data><Data Name='ParentProcessId'>2320</Data><Data Name='ParentImage'>C:\Windows\System32\cmd.exe</Data><Data Name='ParentCommandLine'>cmd /c ""C:\Users\IEuser\Desktop\launcher.bat" "</Data></EventData></Event>
```
##### Key Indicator

| Field        | Value                                            | Comments |
| ------------ | ------------------------------------------------ | -------- |
| EventID      | 1                                                |          |
| process_exec | cmd.exe                                          |          |
| process_id   | 2320                                             |          |
| cmdline      | cmd /c ""C:\Users\IEuser\Desktop\launcher.bat" " |          |

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-03T00:26:42.364910700Z'/><EventRecordID>14242</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-03 00:26:42.364</Data><Data Name='ProcessGuid'>{84453EAB-30C2-5FC8-B4AA-080200000000}</Data><Data Name='ProcessId'>3316</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='FileVersion'>6.1.7600.16385 (win7_rtm.090713-1255)</Data><Data Name='Description'>Windows PowerShell</Data><Data Name='Product'>Microsoft® Windows® Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  -nol -nop -ep bypass "[IO.File]::ReadAllText('C:\Users\IEuser\Desktop\launcher.bat')|iex" </Data><Data Name='CurrentDirectory'>C:\Users\IEuser\Desktop\</Data><Data Name='User'>WIN-40TITGP9BI7\IEuser</Data><Data Name='LogonGuid'>{84453EAB-6BA3-5FC6-A0CC-080000000000}</Data><Data Name='LogonId'>0x8cca0</Data><Data Name='TerminalSessionId'>2</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=852D67A27E454BD389FA7F02A8CBE23F,SHA256=A8FDBA9DF15E41B6F5C69C79F66A26A9D48E174F9E7018A371600B866867DAB8,IMPHASH=F2C0E8A5BD10DBC167455484050CD683</Data><Data Name='ParentProcessGuid'>{84453EAB-30C2-5FC8-00A8-080200000000}</Data><Data Name='ParentProcessId'>2320</Data><Data Name='ParentImage'>C:\Windows\System32\cmd.exe</Data><Data Name='ParentCommandLine'>cmd /c ""C:\Users\IEuser\Desktop\launcher.bat" "</Data></EventData></Event>
```

##### Key Indicator

| Field             | Value                                                                                                                                                    | Comments |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| EventID           | 1                                                                                                                                                        |          |
| process_exec      | powershell.exe                                                                                                                                           |          |
| process_id        | 3316                                                                                                                                                     |          |
| parent_process_id | 2320                                                                                                                                                     |          |
| cmdline           | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nol -nop -ep bypass "[IO.File]::ReadAllText('C:\Users\IEuser\Desktop\launcher.bat') \| iex" |          |


```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-03T00:26:42.505311600Z'/><EventRecordID>14243</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-03 00:26:42.505</Data><Data Name='ProcessGuid'>{84453EAB-30C2-5FC8-D2B6-080200000000}</Data><Data Name='ProcessId'>2924</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='FileVersion'>6.1.7600.16385 (win7_rtm.090713-1255)</Data><Data Name='Description'>Windows PowerShell</Data><Data Name='Product'>Microsoft® Windows® Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  -noP -sta -w 1 -enc //empire generated payload, 5137bytes long //</Data><Data Name='CurrentDirectory'>C:\Users\IEuser\Desktop\</Data><Data Name='User'>WIN-40TITGP9BI7\IEuser</Data><Data Name='LogonGuid'>{84453EAB-6BA3-5FC6-A0CC-080000000000}</Data><Data Name='LogonId'>0x8cca0</Data><Data Name='TerminalSessionId'>2</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=852D67A27E454BD389FA7F02A8CBE23F,SHA256=A8FDBA9DF15E41B6F5C69C79F66A26A9D48E174F9E7018A371600B866867DAB8,IMPHASH=F2C0E8A5BD10DBC167455484050CD683</Data><Data Name='ParentProcessGuid'>{84453EAB-30C2-5FC8-B4AA-080200000000}</Data><Data Name='ParentProcessId'>3316</Data><Data Name='ParentImage'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='ParentCommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  -nol -nop -ep bypass "[IO.File]::ReadAllText('C:\Users\IEuser\Desktop\launcher.bat')|iex" </Data></EventData></Event>
```

##### Key Indicator

| Field             | Value                                                                         | Comments |
| ----------------- | ----------------------------------------------------------------------------- | -------- |
| EventID           | 1                                                                             |          |
| process_exec      | powershell.exe                                                                |          |
| process_id        | 2924                                                                          |          |
| cmdline           | powershell  -noP -sta -w 1 -enc //empire generated payload, 5137bytes long // |          |
| parent_process_id | 3316                                                                          |          |


```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>3</EventID><Version>5</Version><Level>4</Level><Task>3</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-03T00:26:47.762545300Z'/><EventRecordID>14244</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='2332'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-03 00:26:45.094</Data><Data Name='ProcessGuid'>{84453EAB-30C2-5FC8-D2B6-080200000000}</Data><Data Name='ProcessId'>2924</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='User'>WIN-40TITGP9BI7\IEuser</Data><Data Name='Protocol'>tcp</Data><Data Name='Initiated'>true</Data><Data Name='SourceIsIpv6'>false</Data><Data Name='SourceIp'>192.168.254.47</Data><Data Name='SourceHostname'>WIN-40TITGP9BI7</Data><Data Name='SourcePort'>51653</Data><Data Name='SourcePortName'>-</Data><Data Name='DestinationIsIpv6'>false</Data><Data Name='DestinationIp'>192.168.254.46</Data><Data Name='DestinationHostname'>-</Data><Data Name='DestinationPort'>80</Data><Data Name='DestinationPortName'>http</Data></EventData></Event>
```

##### Key Indicator

| Field        | Value          | Comments                                                           |
| ------------ | -------------- | ------------------------------------------------------------------ |
| EventID      | 3              |                                                                    |
| process_exec | powershell.exe |                                                                    |
| process_id   | 2924           |                                                                    |
| dest_ip      | 192.168.254.46 | my test lab c2                                                     |
| dest_port    | 80             | depends on the empire listener type, in this simulation i set http |

