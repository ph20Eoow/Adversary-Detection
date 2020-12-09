# Situation Awareness - Winenum

## Goal 
| Simulation # | Stager Option                           |
| ------------ | --------------------------------------- |
| 1            | usermodule situation_awareness/host/winenum |

## Technical Context
### Assumption
* Attacker is a low-priv user 
* The C2 connection has established 

### Simulation 1
This attack try to enum to local system on a low-priv account

##### Raw Sysmon Event
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
        <Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}' />
        <EventID>1</EventID>
        <Version>5</Version>
        <Level>4</Level>
        <Task>1</Task>
        <Opcode>0</Opcode>
        <Keywords>0x8000000000000000</Keywords>
        <TimeCreated SystemTime='2020-12-09T10:57:26.8067557Z' />
        <EventRecordID>28761</EventRecordID>
        <Correlation />
        <Execution ProcessID='2728' ThreadID='3504' />
        <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
        <Computer>DESKTOP-DS6SIME</Computer>
        <Security UserID='S-1-5-18' />
    </System>
    <EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-09 10:57:26.804</Data><Data
            Name='ProcessGuid'>{f2b94391-ad96-5fd0-a51a-000000000600}</Data><Data Name='ProcessId'>10120</Data><Data
            Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data
            Name='FileVersion'>10.0.19041.546 (WinBuild.160101.0800)</Data><Data Name='Description'>Windows
            PowerShell</Data><Data Name='Product'>Microsoft® Windows® Operating System</Data><Data
            Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data
            Name='CommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noninteractive -Sta
            -encodedCommand
            CgAgACAAIAAgACAAIAAgACAAIAAgACAAIABBAGQAZAAtAFQAeQBwAGUAIAAtAEEAcwBzAGUAbQBiAGwAeQAgAFAAcgBlAHMAZQBuAHQAYQB0AGkAbwBuAEMAbwByAGUACgAgACAAIAAgACAAIAAgACAAIAAgACAAIABbAFcAaQBuAGQAbwB3AHMALgBDAGwAaQBwAGIAbwBhAHIAZABdADoAOgBHAGUAdABUAGUAeAB0ACgAKQAgAC0AcgBlAHAAbABhAGMAZQAgACIAYAByACIALAAgACcAJwAgAC0AcwBwAGwAaQB0ACAAIgBgAG4AIgAgACAACgAgACAAIAAgACAAIAAgACAA
            -inputFormat xml -outputFormat xml</Data><Data Name='CurrentDirectory'>C:\Users\victim\</Data><Data
            Name='User'>DESKTOP-DS6SIME\victim</Data><Data
            Name='LogonGuid'>{f2b94391-5f46-5fd0-2cb0-820100000000}</Data><Data Name='LogonId'>0x182b02c</Data><Data
            Name='TerminalSessionId'>4</Data><Data Name='IntegrityLevel'>Medium</Data><Data
            Name='Hashes'>MD5=04029E121A0CFA5991749937DD22A1D9,SHA256=9F914D42706FE215501044ACD85A32D58AAEF1419D404FDDFA5D3B48F66CCD9F,IMPHASH=7C955A0ABC747F57CCC4324480737EF7</Data><Data
            Name='ParentProcessGuid'>{f2b94391-a9dc-5fd0-1f1a-000000000600}</Data><Data
            Name='ParentProcessId'>15292</Data><Data
            Name='ParentImage'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data
            Name='ParentCommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noP -sta -w 1 -enc
            //5096 bytes payload//</Data></EventData>
</Event>
```

##### Key Indicator

| Field             | Value                                                                         | Comments |
| ----------------- | ----------------------------------------------------------------------------- | -------- |
| EventID           | 1                                                                             |          |
| process_exec      | powershell.exe                                                                |          |
| process_id   | 10120|          |
| parent_process_id   | 15292|          |
|parent_process_exec| powershell.exe||
| parent_process | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noP -sta -w 1 -enc //5096 bytes payload//||
| cmdline| "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noninteractive -Sta -encodedCommand CgAgACAAIAAgACAAIAAgACAAIAAgACAAIABBAGQAZAAtAFQAeQBwAGUAIAAtAEEAcwBzAGUAbQBiAGwAeQAgAFAAcgBlAHMAZQBuAHQAYQB0AGkAbwBuAEMAbwByAGUACgAgACAAIAAgACAAIAAgACAAIAAgACAAIABbAFcAaQBuAGQAbwB3AHMALgBDAGwAaQBwAGIAbwBhAHIAZABdADoAOgBHAGUAdABUAGUAeAB0ACgAKQAgAC0AcgBlAHAAbABhAGMAZQAgACIAYAByACIALAAgACcAJwAgAC0AcwBwAGwAaQB0ACAAIgBgAG4AIgAgACAACgAgACAAIAAgACAAIAAgACAA -inputFormat xml -outputFormat xml||



##### Raw Powershell Event
```xml
12/09/2020 06:55:57 PM
LogName=Microsoft-Windows-PowerShell/Operational
EventCode=4103
EventType=4
ComputerName=DESKTOP-DS6SIME
User=NOT_TRANSLATED
Sid=S-1-5-21-2242309504-3943410855-4141223597-1003
SidType=0
SourceName=Microsoft-Windows-PowerShell
Type=Information
RecordNumber=153
Keywords=None
TaskCategory=Executing Pipeline
OpCode=To be used when operation is just executing a method
Message=CommandInvocation(Add-Type): "Add-Type"
ParameterBinding(Add-Type): name="AssemblyName"; value="System.DirectoryServices.AccountManagement"


Context:
        Severity = Informational
        Host Name = Default Host
        Host Version = 5.1.19041.610
        Host ID = b62a019d-6f2b-4af5-940d-2bf1105a8a78
        Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noP -sta -w 1 -enc //5096 bytes payload//
        Engine Version = 5.1.19041.610
        Runspace ID = f7c605f8-a25a-4234-bde5-26eb70350c31
        Pipeline ID = 1
        Command Name = Add-Type
        Command Type = Cmdlet
        Script Name = 
        Command Path = 
        Sequence Number = 34
        User = DESKTOP-DS6SIME\victim
        Connected User = 
        Shell ID = Microsoft.PowerShell


User Data:
```

##### Key Indicator

| Field             | Value                                                                         | Comments |
| ----------------- | ----------------------------------------------------------------------------- | -------- |
| EventID           | 4103                                                                             |          |
| Message      | CommandInvocation(Add-Type): "Add-Type" ParameterBinding(Add-Type): name="AssemblyName"; value="System.DirectoryServices.AccountManagement" Context: Severity = Informational Host Name = Default Host Host Version = 5.1.19041.610 Host ID = b62a019d-6f2b-4af5-940d-2bf1105a8a78 Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noP -sta -w 1 -enc //5096 bytes payload// Engine Version = 5.1.19041.610 Runspace ID = f7c605f8-a25a-4234-bde5-26eb70350c31 Pipeline ID = 1 Command Name = Add-Type Command Type = Cmdlet Script Name = Command Path = Sequence Number = 34 User = DESKTOP-DS6SIME\victim Connected User = Shell ID = Microsoft.PowerShell User Data:	
|          |
```xml
12/09/2020 06:56:02 PM
LogName=Microsoft-Windows-PowerShell/Operational
EventCode=4100
EventType=3
ComputerName=DESKTOP-DS6SIME
User=NOT_TRANSLATED
Sid=S-1-5-21-2242309504-3943410855-4141223597-1003
SidType=0
SourceName=Microsoft-Windows-PowerShell
Type=Warning
RecordNumber=154
Keywords=None
TaskCategory=Executing Pipeline
OpCode=To be used when an exception is raised
Message=Error Message = Exception calling ".ctor" with "2" argument(s): "The server could not be contacted."
Fully Qualified Error ID = ConstructorInvokedThrowException,Microsoft.PowerShell.Commands.NewObjectCommand


Context:
        Severity = Warning
        Host Name = Default Host
        Host Version = 5.1.19041.610
        Host ID = b62a019d-6f2b-4af5-940d-2bf1105a8a78
        Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noP -sta -w 1 -enc //5096 bytes payload//
        Engine Version = 5.1.19041.610
        Runspace ID = f7c605f8-a25a-4234-bde5-26eb70350c31
        Pipeline ID = 1
        Command Name = New-Object
        Command Type = Cmdlet
        Script Name = 
        Command Path = 
        Sequence Number = 35
        User = DESKTOP-DS6SIME\victim
        Connected User = 
        Shell ID = Microsoft.PowerShell


User Data:
```

##### Key Indicator

| Field             | Value                                                                         | Comments |
| ----------------- | ----------------------------------------------------------------------------- | -------- |
| EventID           | 4100                                                                             |          |
| Message      | Error Message = Exception calling ".ctor" with "2" argument(s): "The server could not be contacted." Fully Qualified Error ID = ConstructorInvokedThrowException,Microsoft.PowerShell.Commands.NewObjectCommand Context: Severity = Warning Host Name = Default Host Host Version = 5.1.19041.610 Host ID = b62a019d-6f2b-4af5-940d-2bf1105a8a78 Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noP -sta -w 1 -enc //5096 bytes payload//  Engine Version = 5.1.19041.610 Runspace ID = f7c605f8-a25a-4234-bde5-26eb70350c31 Pipeline ID = 1 Command Name = New-Object Command Type = Cmdlet Script Name = Command Path = Sequence Number = 35 User = DESKTOP-DS6SIME\victim Connected User = Shell ID = Microsoft.PowerShell User Data:|          |
