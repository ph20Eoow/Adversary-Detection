# Empire Stager

## Goal 
| Simulation # | Stager Option  |
| ------------ | -------------- |
| 1            | multi/launcher |


## Technical Context
### Simulation 1 
This is the example to study the behavior of the empire generated payload

#### Payload Generation
```bash
(Empire) > usestager multi/launcher
```

#### Attack Begin

1. Pasted the payload on victim machine via cmd.exe
2. the payload successfully callback to C2 server


##### Raw Sysmon Event
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-02T23:43:07.246776900Z'/><EventRecordID>13915</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-02 23:43:07.246</Data><Data Name='ProcessGuid'>{84453EAB-268B-5FC8-1EC2-FB0100000000}</Data><Data Name='ProcessId'>1356</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='FileVersion'>6.1.7600.16385 (win7_rtm.090713-1255)</Data><Data Name='Description'>Windows PowerShell</Data><Data Name='Product'>Microsoft® Windows® Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>powershell  -noP -sta -w 1 -enc //empire generated payload, 5137bytes long //</Data><Data Name='CurrentDirectory'>C:\Users\IEuser\</Data><Data Name='User'>WIN-40TITGP9BI7\IEuser</Data><Data Name='LogonGuid'>{84453EAB-6BA3-5FC6-A0CC-080000000000}</Data><Data Name='LogonId'>0x8cca0</Data><Data Name='TerminalSessionId'>2</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=852D67A27E454BD389FA7F02A8CBE23F,SHA256=A8FDBA9DF15E41B6F5C69C79F66A26A9D48E174F9E7018A371600B866867DAB8,IMPHASH=F2C0E8A5BD10DBC167455484050CD683</Data><Data Name='ParentProcessGuid'>{84453EAB-2686-5FC8-88BF-FB0100000000}</Data><Data Name='ParentProcessId'>1136</Data><Data Name='ParentImage'>C:\Windows\System32\cmd.exe</Data><Data Name='ParentCommandLine'>"C:\Windows\system32\cmd.exe" </Data></EventData></Event>
```

##### Key Indicator

| Field        | Value                                                                         | Comments |
| ------------ | ----------------------------------------------------------------------------- | -------- |
| EventID      | 1                                                                             |          |
| process_exec | powershell.exe                                                                |          |
| process_id   | 1356                                                                          |          |
| cmdline      | powershell  -noP -sta -w 1 -enc //empire generated payload, 5137bytes long // |          |

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>3</EventID><Version>5</Version><Level>4</Level><Task>3</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-02T23:43:13.642776900Z'/><EventRecordID>13924</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='2332'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-02 23:43:09.852</Data><Data Name='ProcessGuid'>{84453EAB-268B-5FC8-1EC2-FB0100000000}</Data><Data Name='ProcessId'>1356</Data><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='User'>WIN-40TITGP9BI7\IEuser</Data><Data Name='Protocol'>tcp</Data><Data Name='Initiated'>true</Data><Data Name='SourceIsIpv6'>false</Data><Data Name='SourceIp'>192.168.254.47</Data><Data Name='SourceHostname'>WIN-40TITGP9BI7</Data><Data Name='SourcePort'>51593</Data><Data Name='SourcePortName'>-</Data><Data Name='DestinationIsIpv6'>false</Data><Data Name='DestinationIp'>192.168.254.46</Data><Data Name='DestinationHostname'>-</Data><Data Name='DestinationPort'>80</Data><Data Name='DestinationPortName'>http</Data></EventData></Event>
```

##### Key Indicator

| Field        | Value          | Comments                                                           |
| ------------ | -------------- | ------------------------------------------------------------------ |
| EventID      | 3              |                                                                    |
| process_exec | powershell.exe |                                                                    |
| process_id   | 1356           |                                                                    |
| dest_ip      | 192.168.254.46 | my test lab c2                                                     |
| dest_port    | 80             | depends on the empire listener type, in this simulation i set http |

##### Raw Powershell Event
```xml
12/09/2020 06:41:32 PM
LogName=Microsoft-Windows-PowerShell/Operational
EventCode=4104
EventType=5
ComputerName=DESKTOP-DS6SIME
User=NOT_TRANSLATED
Sid=S-1-5-21-2242309504-3943410855-4141223597-1003
SidType=0
SourceName=Microsoft-Windows-PowerShell
Type=Verbose
RecordNumber=148
Keywords=None
TaskCategory=Execute a Remote Command
OpCode=On create calls
Message=Creating Scriptblock text (1 of 1):
powershell -noP -sta -w 1 -enc  //5096 bytes payload//

ScriptBlock ID: 849c7b04-3d0b-4510-beb0-12f222a5ef3c
Path:
```

##### Key Indicator 
| Field   | Value                                                                                                                                                | Comments |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| EventID | 4104                                                                                                                                                 |          |
| Message | Creating Scriptblock text (1 of 1): powershell -noP -sta -w 1 -enc //5096 bytes payload// ScriptBlock ID: 849c7b04-3d0b-4510-beb0-12f222a5ef3c Path: |