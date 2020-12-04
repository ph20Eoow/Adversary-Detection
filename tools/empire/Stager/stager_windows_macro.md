# Empire Stager

## Goal 
| Simulation # | Stager Option |
| ------------ | ------------- |
| 1            | windows_macro |

## Technical Context
### Simulation 1
This attack example inject the generated payload into M$ office documents macro

#### Payload Generation
```bash
(Empire) > usestager windows/macro
(Empire: stager/windows/macro) > set Listener http
(Empire: stager/windows/macro) > generate
```
#### Attack Begin

1. Open the document with injected payload macro

##### Raw Sysmon Event
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T00:31:46.774152800Z'/><EventRecordID>17831</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-04 00:31:46.771</Data><Data Name='ProcessGuid'>{84453EAB-8372-5FC9-10CD-380200000000}</Data><Data Name='ProcessId'>1596</Data><Data Name='Image'>C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE</Data><Data Name='FileVersion'>16.0.12527.21330</Data><Data Name='Description'>Microsoft Word</Data><Data Name='Product'>Microsoft Office</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>WinWord.exe</Data><Data Name='CommandLine'>"C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\IEuser\Downloads\malicious.docx" /o "u"</Data><Data Name='CurrentDirectory'>C:\Users\IEuser\Downloads\</Data><Data Name='User'>WIN-40TITGP9BI7\IEuser</Data><Data Name='LogonGuid'>{84453EAB-6BA3-5FC6-A0CC-080000000000}</Data><Data Name='LogonId'>0x8cca0</Data><Data Name='TerminalSessionId'>2</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=3BA3D1BEDE682DAFA7392BB073381E7D,SHA256=E44F444EAA456F46B1ED60B5410298E4C324607BB48B73940F0F745F0305A78A,IMPHASH=E35903DD5F449996A8A560239CCEDAFA</Data><Data Name='ParentProcessGuid'>{84453EAB-6BA3-5FC6-99E6-080000000000}</Data><Data Name='ParentProcessId'>3004</Data><Data Name='ParentImage'>C:\Windows\explorer.exe</Data><Data Name='ParentCommandLine'>C:\Windows\Explorer.EXE</Data></EventData></Event>
```
##### Key Indicator

| Field        | Value                                                                                                                    | Comments |
| ------------ | ------------------------------------------------------------------------------------------------------------------------ | -------- |
| EventID      | 1                                                                                                                        |          |
| process_exec | WINWORD.EXE                                                                                                              |          |
| process_id   | 1596                                                                                                                     |          |
| cmdline      | "C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\IEuser\Downloads\malicious.docx" /o "u" |          |

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T00:31:47.061152800Z'/><EventRecordID>17833</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-04 00:31:47.056</Data><Data Name='ProcessGuid'>{84453EAB-8373-5FC9-2308-390200000000}</Data><Data Name='ProcessId'>704</Data><Data Name='Image'>C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE</Data><Data Name='FileVersion'>16.0.12527.21330</Data><Data Name='Description'>Microsoft Word</Data><Data Name='Product'>Microsoft Office</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>WinWord.exe</Data><Data Name='CommandLine'>"C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE"  /Embedding /disablescaling</Data><Data Name='CurrentDirectory'>C:\Program Files (x86)\Microsoft Office\Root\Office16\</Data><Data Name='User'>WIN-40TITGP9BI7\IEuser</Data><Data Name='LogonGuid'>{84453EAB-6BA3-5FC6-A0CC-080000000000}</Data><Data Name='LogonId'>0x8cca0</Data><Data Name='TerminalSessionId'>2</Data><Data Name='IntegrityLevel'>Low</Data><Data Name='Hashes'>MD5=3BA3D1BEDE682DAFA7392BB073381E7D,SHA256=E44F444EAA456F46B1ED60B5410298E4C324607BB48B73940F0F745F0305A78A,IMPHASH=E35903DD5F449996A8A560239CCEDAFA</Data><Data Name='ParentProcessGuid'>{84453EAB-8372-5FC9-10CD-380200000000}</Data><Data Name='ParentProcessId'>1596</Data><Data Name='ParentImage'>C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE</Data><Data Name='ParentCommandLine'>"C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\IEuser\Downloads\malicious.docx" /o "u"</Data></EventData></Event>
```
##### Key Indicator

| Field        | Value                                                                                          | Comments |
| ------------ | ---------------------------------------------------------------------------------------------- | -------- |
| EventID      | 1                                                                                              |          |
| process_exec | WINWORD.EXE                                                                                    |          |
| process_id   | 1596                                                                                           |          |
| cmdline      | "C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE" /Embedding /disablescaling |          |


```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>13</EventID><Version>2</Version><Level>4</Level><Task>13</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T00:31:59.771152800Z'/><EventRecordID>17837</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>Context,ProtectedModeExitOrMacrosUsed</Data><Data Name='EventType'>SetValue</Data><Data Name='UtcTime'>2020-12-04 00:31:59.771</Data><Data Name='ProcessGuid'>{84453EAB-8372-5FC9-10CD-380200000000}</Data><Data Name='ProcessId'>1596</Data><Data Name='Image'>C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE</Data><Data Name='TargetObject'>HKU\S-1-5-21-2892772840-4280103526-640991184-1000\Software\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords\%USERPROFILE%/Downloads/malicious.docx</Data><Data Name='Details'>Binary Data</Data></EventData></Event>
```
##### Key Indicator

| Field         | Value                                                                                                                                                                | Comments                                                              |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| EventID       | 13                                                                                                                                                                   |                                                                       |
| process_exec  | WINWORD.EXE                                                                                                                                                          |                                                                       |
| process_id    | 1596                                                                                                                                                                 |                                                                       |
| registry_path | HKU\S-1-5-21-2892772840-4280103526-640991184-1000\Software\Microsoft\Office\16.0\Word\Security\Trusted Documents\TrustRecords\%USERPROFILE%/Downloads/malicious.docx | This is the event when u trust that doc, which allow to run the macro |

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T00:31:59.854152800Z'/><EventRecordID>17839</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-04 00:31:59.845</Data><Data Name='ProcessGuid'>{84453EAB-837F-5FC9-88AE-390200000000}</Data><Data Name='ProcessId'>2472</Data><Data Name='Image'>C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='FileVersion'>6.1.7600.16385 (win7_rtm.090713-1255)</Data><Data Name='Description'>Windows PowerShell</Data><Data Name='Product'>Microsoft® Windows® Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -noP -sta -w 1 -enc //<-- 5097bytes long payload -->//</Data><Data Name='CurrentDirectory'>C:\Users\IEuser\Downloads\</Data><Data Name='User'>WIN-40TITGP9BI7\IEuser</Data><Data Name='LogonGuid'>{84453EAB-6BA3-5FC6-A0CC-080000000000}</Data><Data Name='LogonId'>0x8cca0</Data><Data Name='TerminalSessionId'>2</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=92F44E405DB16AC55D97E3BFE3B132FA,SHA256=6C05E11399B7E3C8ED31BAE72014CF249C144A8F4A2C54A758EB2E6FAD47AEC7,IMPHASH=96BA691B035D05F44E35AB23F6BA946C</Data><Data Name='ParentProcessGuid'>{84453EAB-8372-5FC9-10CD-380200000000}</Data><Data Name='ParentProcessId'>1596</Data><Data Name='ParentImage'>C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE</Data><Data Name='ParentCommandLine'>"C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\IEuser\Downloads\malicious.docx" /o "u"</Data></EventData></Event>
```
##### Key Indicator

| Field             | Value                                                                                                            | Comments |
| ----------------- | ---------------------------------------------------------------------------------------------------------------- | -------- |
| EventID           | 1                                                                                                                |          |
| process_exec      | powershell.exe                                                                                                   |          |
| process_id        | 2472                                                                                                             |          |
| parent_process_id | 1596                                                                                                             |          |
| cmdline           | C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -noP -sta -w 1 -enc //<-- 5097bytes long payload -->// |          |


```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T00:31:59.854152800Z'/><EventRecordID>17839</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-04 00:31:59.845</Data><Data Name='ProcessGuid'>{84453EAB-837F-5FC9-88AE-390200000000}</Data><Data Name='ProcessId'>2472</Data><Data Name='Image'>C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='FileVersion'>6.1.7600.16385 (win7_rtm.090713-1255)</Data><Data Name='Description'>Windows PowerShell</Data><Data Name='Product'>Microsoft® Windows® Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -noP -sta -w 1 -enc //<-- 5097bytes long payload -->//</Data><Data Name='CurrentDirectory'>C:\Users\IEuser\Downloads\</Data><Data Name='User'>WIN-40TITGP9BI7\IEuser</Data><Data Name='LogonGuid'>{84453EAB-6BA3-5FC6-A0CC-080000000000}</Data><Data Name='LogonId'>0x8cca0</Data><Data Name='TerminalSessionId'>2</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=92F44E405DB16AC55D97E3BFE3B132FA,SHA256=6C05E11399B7E3C8ED31BAE72014CF249C144A8F4A2C54A758EB2E6FAD47AEC7,IMPHASH=96BA691B035D05F44E35AB23F6BA946C</Data><Data Name='ParentProcessGuid'>{84453EAB-8372-5FC9-10CD-380200000000}</Data><Data Name='ParentProcessId'>1596</Data><Data Name='ParentImage'>C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE</Data><Data Name='ParentCommandLine'>"C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\IEuser\Downloads\malicious.docx" /o "u"</Data></EventData></Event>
```
##### Key Indicator

| Field             | Value          | Comments                                                           |
| ----------------- | -------------- | ------------------------------------------------------------------ |
| EventID           | 3              |                                                                    |
| process_exec      | powershell.exe |                                                                    |
| process_id        | 2472           |                                                                    |
| parent_process_id | 1596           |                                                                    |
| dest_ip           | 192.168.254.46 | my test lab c2                                                     |
| dest_port         | 80             | depends on the empire listener type, in this simulation i set http |


