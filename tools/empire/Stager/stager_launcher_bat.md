# Empire Stager

## Hypothesis 
The adversary used empire' launcher_bat stager to execute code in the environment. This attack example can be leveraged by attackers in a physical way, such as rubber ducky.

## Technical Context
None

## Analytics
#### Payload Generation
```bash
(Empire) > usestager windows/launcher_bat
```

#### Behavior Summary
1. Generate the .bat payload
2. User click the .bat file, in reality it can be executed by autorun.inf

## Analytic I

| Field                | Value                                                                     |
| -------------------- | ------------------------------------------------------------------------- |
| LogName              | Security                                                                  |
| EventCode            | 4688                                                                      |
| New_Process_ID       | 0x1374                                                                    |
| New_Process_name     | C:\Windows\system32\cmd.exe                                               |
| Process_Command_Line | C:\Windows\system32\cmd.exe /c ""C:\Users\vagrant\Downloads\launcher.bat" |
| TaskCatergory        | Process Creation                                                          |

```xml
12/15/2020 04:09:20 AM
LogName=Security
EventCode=4688
EventType=0
ComputerName=win10.windomain.local
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=1132967
Keywords=Audit Success
TaskCategory=Process Creation
OpCode=Info
Message=A new process has been created.

Creator Subject:
	Security ID:		S-1-5-21-3681719425-3201420387-1996724379-1000
	Account Name:		vagrant
	Account Domain:		WIN10
	Logon ID:		0x43784F

Target Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Process Information:
	New Process ID:		0x1374
	New Process Name:	C:\Windows\System32\cmd.exe
	Token Elevation Type:	%%1936
	Mandatory Label:		S-1-16-12288
	Creator Process ID:	0xc08
	Creator Process Name:	C:\Windows\explorer.exe
	Process Command Line:	C:\Windows\system32\cmd.exe /c ""C:\Users\vagrant\Downloads\launcher.bat" "

Token Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.

Type 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.

Type 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.

Type 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator.
```

## Analytic II

| Field                | Value                                                                                                                                                     |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LogName              | Security                                                                                                                                                  |
| EventCode            | 4688                                                                                                                                                      |
| Creator_Process_ID   | 0x1374                                                                                                                                                    |
| New_Process_ID       | 0x25f4                                                                                                                                                    |
| New_Process_name     | Creator_Process_ID                                                                                                                                        |
| Process_Command_Line | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nol -nop -ep bypass "[IO.File]::ReadAllText('C:\Users\vagrant\Downloads\launcher.bat')\|iex" |
|                      |
| TaskCatergory        | Process Creation                                                                                                                                          |

```xml
12/15/2020 04:09:20 AM
LogName=Security
EventCode=4688
EventType=0
ComputerName=win10.windomain.local
SourceName=Microsoft Windows security auditing.
Type=Information
RecordNumber=1132969
Keywords=Audit Success
TaskCategory=Process Creation
OpCode=Info
Message=A new process has been created.

Creator Subject:
	Security ID:		S-1-5-21-3681719425-3201420387-1996724379-1000
	Account Name:		vagrant
	Account Domain:		WIN10
	Logon ID:		0x43784F

Target Subject:
	Security ID:		S-1-0-0
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Process Information:
	New Process ID:		0x25f4
	New Process Name:	C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
	Token Elevation Type:	%%1936
	Mandatory Label:		S-1-16-12288
	Creator Process ID:	0x1374
	Creator Process Name:	C:\Windows\System32\cmd.exe
	Process Command Line:	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  -nol -nop -ep bypass "[IO.File]::ReadAllText('C:\Users\vagrant\Downloads\launcher.bat')|iex" 

Token Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.

Type 1 is a full token with no privileges removed or groups disabled.  A full token is only used if User Account Control is disabled or if the user is the built-in Administrator account or a service account.

Type 2 is an elevated token with no privileges removed or groups disabled.  An elevated token is used when User Account Control is enabled and the user chooses to start the program using Run as administrator.  An elevated token is also used when an application is configured to always require administrative privilege or to always require maximum privilege, and the user is a member of the Administrators group.

Type 3 is a limited token with administrative privileges removed and administrative groups disabled.  The limited token is used when User Account Control is enabled, the application does not require administrative privilege, and the user does not choose to start the program using Run as administrator.
```
## Analytic III

| Field        | Value              |
| ------------ | ------------------ |
| LogName      | Windows PowerShell |
| EventCode    | 600                |
| TaskCategory | Provider Lifecycle |

```xml
12/15/2020 04:09:22 AM
LogName=Windows PowerShell
EventCode=600
EventType=4
ComputerName=win10.windomain.local
SourceName=PowerShell
Type=Information
RecordNumber=543858
Keywords=Classic
TaskCategory=Provider Lifecycle
OpCode=Info
Message=Provider "Registry" is Started. 

Details: 
	ProviderName=Registry
	NewProviderState=Started

	SequenceNumber=1

	HostName=ConsoleHost
	HostVersion=5.1.18362.1
	HostId=9502c33c-d708-4005-9ab5-88185e65817e
	HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nol -nop -ep bypass [IO.File]::ReadAllText('C:\Users\vagrant\Downloads\launcher.bat')|iex
	EngineVersion=
	RunspaceId=
	PipelineId=
	CommandName=
	CommandType=
	ScriptName=
	CommandPath=
	CommandLine=
```

## Analytic IV

| Field             | Value                                                                                                                                                      |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LogName           | Microsoft-Windows-Sysmon/Operational                                                                                                                       |
| EventCode         | 1                                                                                                                                                          |
| TaskCategory      | Process Create                                                                                                                                             |
| RuleName          | technique_id=T1059.001,technique_name=PowerShell                                                                                                           |
| ProcessId         | 3988                                                                                                                                                       |
| CommandLine       | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noP -sta -w 1 -enc //5112 byte payload//                                                      |
| ParentProcessId   | 9716                                                                                                                                                       |
| ParentImage       | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe                                                                                                  |
| ParentCommandLine | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  -nol -nop -ep bypass "[IO.File]::ReadAllText('C:\Users\vagrant\Downloads\launcher.bat')\|iex" |
| ProcessGuid       | {bac4bdbc-36f2-5fd8-570d-000000000700}                                                                                                                     |

```xml
12/15/2020 04:09:22 AM
LogName=Microsoft-Windows-Sysmon/Operational
EventCode=1
EventType=4
ComputerName=win10.windomain.local
User=NOT_TRANSLATED
Sid=S-1-5-18
SidType=0
SourceName=Microsoft-Windows-Sysmon
Type=Information
RecordNumber=165472
Keywords=None
TaskCategory=Process Create (rule: ProcessCreate)
OpCode=Info
Message=Process Create:
RuleName: technique_id=T1059.001,technique_name=PowerShell
UtcTime: 2020-12-15 04:09:22.513
ProcessGuid: {bac4bdbc-36f2-5fd8-570d-000000000700}
ProcessId: 3988
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
FileVersion: 10.0.18362.1 (WinBuild.160101.0800)
Description: Windows PowerShell
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: PowerShell.EXE
CommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noP -sta -w 1 -enc //5112 byte payload//
CurrentDirectory: C:\Users\vagrant\Downloads\
User: WIN10\vagrant
LogonGuid: {bac4bdbc-151b-5fd5-4f78-430000000000}
LogonId: 0x43784F
TerminalSessionId: 2
IntegrityLevel: High
Hashes: SHA1=36C5D12033B2EAF251BAE61C00690FFB17FDDC87,MD5=CDA48FC75952AD12D99E526D0B6BF70A,SHA256=908B64B1971A979C7E3E8CE4621945CBA84854CB98D76367B791A6E22B5F6D53,IMPHASH=A7CEFACDDA74B13CD330390769752481
ParentProcessGuid: {bac4bdbc-36f0-5fd8-560d-000000000700}
ParentProcessId: 9716
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"  -nol -nop -ep bypass "[IO.File]::ReadAllText('C:\Users\vagrant\Downloads\launcher.bat')|iex"
```

## Analytic V
| Field        | Value                                                     |
| ------------ | --------------------------------------------------------- |
| LogName      | Microsoft-Windows-Sysmon/Operational                      |
| EventCode    | 7                                                         |
| ProcessId    | 3988                                                      |
| Image        | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| ImageLoaded  | C:\Windows\System32\wbem\wmiutils.dll                     |
| TaskCategory | Image loaded (rule: ImageLoad)                            |

```xml
12/15/2020 04:09:23 AM
LogName=Microsoft-Windows-Sysmon/Operational
EventCode=7
EventType=4
ComputerName=win10.windomain.local
User=NOT_TRANSLATED
Sid=S-1-5-18
SidType=0
SourceName=Microsoft-Windows-Sysmon
Type=Information
RecordNumber=165481
Keywords=None
TaskCategory=Image loaded (rule: ImageLoad)
OpCode=Info
Message=Image loaded:
RuleName: technique_id=T1047,technique_name=Windows Management Instrumentation
UtcTime: 2020-12-15 04:09:23.551
ProcessGuid: {bac4bdbc-36f2-5fd8-570d-000000000700}
ProcessId: 3988
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ImageLoaded: C:\Windows\System32\wbem\wmiutils.dll
FileVersion: 10.0.18362.1 (WinBuild.160101.0800)
Description: WMI
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: wmiutils.dll
Hashes: SHA1=BC609D0AE8E4D79DC586A784DA6E660C25411BAE,MD5=9639A13D44802D3060BAB0072EB7945A,SHA256=45446583DDBD1DA38B545603AF62E305F13DD480B09F4A689BE4ADC98BC4A4AF,IMPHASH=0D31E6D27B954AD879CB4DF742982F1A
Signed: true
Signature: Microsoft Windows
SignatureStatus: Valid
```

## Analytic VI
| Field           | Value                                              |
| --------------- | -------------------------------------------------- |
| LogName         | Microsoft-Windows-Sysmon/Operational               |
| EventCode       | 3                                                  |
| ProcessId       | 3988                                               |
| DestinationIp   | <C2 IP>                                            |
| DestinationPort | 80                                                 |
| TaskCategory    | Network connection detected (rule: NetworkConnect) |

```xml
12/15/2020 04:09:24 AM
LogName=Microsoft-Windows-Sysmon/Operational
EventCode=3
EventType=4
ComputerName=win10.windomain.local
User=NOT_TRANSLATED
Sid=S-1-5-18
SidType=0
SourceName=Microsoft-Windows-Sysmon
Type=Information
RecordNumber=165482
Keywords=None
TaskCategory=Network connection detected (rule: NetworkConnect)
OpCode=Info
Message=Network connection detected:
RuleName: technique_id=T1059.001,technique_name=PowerShell
UtcTime: 2020-12-15 12:06:32.677
ProcessGuid: {bac4bdbc-36f2-5fd8-570d-000000000700}
ProcessId: 3988
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: WIN10\vagrant
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 192.168.254.56
SourceHostname: -
SourcePort: 49581
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 192.168.254.46
DestinationHostname: -
DestinationPort: 80
DestinationPortName: -
```
## Known Bypasses
None

## False Positives
None