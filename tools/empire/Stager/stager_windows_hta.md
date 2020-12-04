# Empire Stager

## Goal 
| Simulation # | Stager Option |
| ------------ | ------------- |
| 1            | windows_hta |

## Technical Context
### Simulation 1
This attack crafted a hta payload inject the generated payload into M$ office documents macro

#### Payload Generation
```bash
(Empire) > usestager windows/macro
(Empire: stager/windows/macro) > set Listener http
(Empire: stager/windows/macro) > generate
```

Outlook Attachment Download
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>11</EventID><Version>2</Version><Level>4</Level><Task>11</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T12:47:39.491363500Z'/><EventRecordID>23138</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>OutlookAttachment</Data><Data Name='UtcTime'>2020-12-04 12:47:39.490</Data><Data Name='ProcessGuid'>{84453EAB-29CB-5FCA-F01B-C20300000000}</Data><Data Name='ProcessId'>5028</Data><Data Name='Image'>C:\Program Files (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE</Data><Data Name='TargetFilename'>C:\Users\IEuser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook\3DVM40KQ\hta_wrapper.html</Data><Data Name='CreationUtcTime'>2020-12-04 12:47:22.074</Data></EventData></Event>
```
##### Key Indicator

| Field        | Value                                                                                          | Comments |
| ------------ | ---------------------------------------------------------------------------------------------- | -------- |
| EventID      | 11                                                                                              |          |
| process_exec | OUTLOOK.EXE                                                                                    |          |
| process_id   | 5028                                                                                           |          |
| file_path      | C:\Users\IEuser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook\3DVM40KQ\hta_wrapper.html |          |


User Open Attachment
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T12:47:40.861500500Z'/><EventRecordID>23141</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-04 12:47:40.860</Data><Data Name='ProcessGuid'>{84453EAB-2FEC-5FCA-2716-DF0300000000}</Data><Data Name='ProcessId'>1392</Data><Data Name='Image'>C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</Data><Data Name='FileVersion'>86.0.4240.198</Data><Data Name='Description'>Google Chrome</Data><Data Name='Product'>Google Chrome</Data><Data Name='Company'>Google LLC</Data><Data Name='OriginalFileName'>chrome.exe</Data><Data Name='CommandLine'>"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --single-argument C:\Users\IEuser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook\3DVM40KQ\hta_wrapper.html</Data><Data Name='CurrentDirectory'>C:\Users\IEuser\AppData\Local\Microsoft\Windows\Temporary Internet Files\</Data><Data Name='User'>WIN-40TITGP9BI7\IEuser</Data><Data Name='LogonGuid'>{84453EAB-6BA3-5FC6-A0CC-080000000000}</Data><Data Name='LogonId'>0x8cca0</Data><Data Name='TerminalSessionId'>2</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=90C30632B1D34656235A1AABC9EC9860,SHA256=9A813A991CCC6687CA05CECA3171487EEA8A1A6230D084BB0FDB2DBB1DAC9E7C,IMPHASH=09C24E8BCF3BD463D2EE5BB0C1223C50</Data><Data Name='ParentProcessGuid'>{84453EAB-29CB-5FCA-F01B-C20300000000}</Data><Data Name='ParentProcessId'>5028</Data><Data Name='ParentImage'>C:\Program Files (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE</Data><Data Name='ParentCommandLine'>"C:\Program Files (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE" </Data></EventData></Event>
```

##### Key Indicator

| Field        | Value                                                                                          | Comments |
| ------------ | ---------------------------------------------------------------------------------------------- | -------- |
| EventID      | 11                                                                                              |          |
| process_exec | CHROME.EXE                                                                                    |          |
| process_id   | 1392                                                                                           |          |
| parent_process_id   | 5028                                                                                           |          |
| cmdline      | "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --single-argument C:\Users\IEuser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook\3DVM40KQ\hta_wrapper.html	
 |          |

HTML Attachment download hta
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>15</EventID><Version>2</Version><Level>4</Level><Task>15</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T12:47:49.686382900Z'/><EventRecordID>23145</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-04 12:47:49.651</Data><Data Name='ProcessGuid'>{84453EAB-2FF5-5FCA-7B47-DF0300000000}</Data><Data Name='ProcessId'>4180</Data><Data Name='Image'>C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</Data><Data Name='TargetFilename'>C:\Users\IEuser\Downloads\payload_hta.hta:Zone.Identifier</Data><Data Name='CreationUtcTime'>2020-12-04 12:47:40.933</Data><Data Name='Hash'>MD5=FBCCF14D504B7B2DBCB5A5BDA75BD93B,SHA256=EACD09517CE90D34BA562171D15AC40D302F0E691B439F91BE1B6406E25F5913,IMPHASH=00000000000000000000000000000000</Data><Data Name='Contents'>[ZoneTransfer]  ZoneId=3  </Data></EventData></Event>
```

##### Key Indicator

| Field        | Value                                                                                          | Comments |
| ------------ | ---------------------------------------------------------------------------------------------- | -------- |
| EventID      | 15                                                                                              |          |
| process_exec | CHROME.EXE                                                                                    |          |
| process_id   | 4180                                                                                           |          |
| file_path      | "C:\Users\IEuser\Downloads\payload_hta.hta:Zone.Identifier" |          |



HTML Attachment download hta. 2
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>11</EventID><Version>2</Version><Level>4</Level><Task>11</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T12:47:40.933507700Z'/><EventRecordID>23142</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>Downloads</Data><Data Name='UtcTime'>2020-12-04 12:47:40.933</Data><Data Name='ProcessGuid'>{84453EAB-2FBC-5FCA-9A1B-DD0300000000}</Data><Data Name='ProcessId'>4388</Data><Data Name='Image'>C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</Data><Data Name='TargetFilename'>C:\Users\IEuser\Downloads\f692e7e2-7146-4fd4-8778-e1f61201bde5.tmp</Data><Data Name='CreationUtcTime'>2020-12-04 12:47:40.933</Data></EventData></Event>
```

##### Key Indicator

| Field        | Value                                                                                          | Comments |
| ------------ | ---------------------------------------------------------------------------------------------- | -------- |
| EventID      | 11                                                                                              |          |
| process_exec | CHROME.EXE                                                                                    |          |
| process_id   | 4388                                                                                           |          |
| file_path      | C:\Users\IEuser\Downloads\f692e7e2-7146-4fd4-8778-e1f61201bde5.tmp |          |


User exectute the hta
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T12:47:52.167631000Z'/><EventRecordID>23146</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-04 12:47:52.148</Data><Data Name='ProcessGuid'>{84453EAB-2FF8-5FCA-2680-DF0300000000}</Data><Data Name='ProcessId'>3700</Data><Data Name='Image'>C:\Windows\SysWOW64\mshta.exe</Data><Data Name='FileVersion'>8.00.7600.16385 (win7_rtm.090713-1255)</Data><Data Name='Description'>Microsoft (R) HTML Application host</Data><Data Name='Product'>Windows® Internet Explorer</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>MSHTA.EXE</Data><Data Name='CommandLine'>"C:\Windows\SysWOW64\mshta.exe" "C:\Users\IEuser\Downloads\payload_hta.hta" </Data><Data Name='CurrentDirectory'>C:\Users\IEuser\Downloads\</Data><Data Name='User'>WIN-40TITGP9BI7\IEuser</Data><Data Name='LogonGuid'>{84453EAB-6BA3-5FC6-A0CC-080000000000}</Data><Data Name='LogonId'>0x8cca0</Data><Data Name='TerminalSessionId'>2</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=E2FE656A79D8F4C4FD70201E7423BDA0,SHA256=DB40B518DEB81B146CC81B0C360AECC84204E3CDC108B1F5F158EE60C1792806,IMPHASH=B75D52B7188D7976DB3843CC449A5655</Data><Data Name='ParentProcessGuid'>{84453EAB-2FBC-5FCA-9A1B-DD0300000000}</Data><Data Name='ParentProcessId'>4388</Data><Data Name='ParentImage'>C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</Data><Data Name='ParentCommandLine'>"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" </Data></EventData></Event>
```

##### Key Indicator

| Field        | Value                                                                                          | Comments |
| ------------ | ---------------------------------------------------------------------------------------------- | -------- |
| EventID      | 1                                                                                              |          |
| process_exec | mshta.exe                                                                                    |          |
| process_id   | 3700                                                                                           |          |
| parent_process_id   | 4388                                                                                           |          |
| cmdline      | "C:\Windows\SysWOW64\mshta.exe" "C:\Users\IEuser\Downloads\payload_hta.hta" |          |

Payload launched
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T12:47:52.212635500Z'/><EventRecordID>23147</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2020-12-04 12:47:52.211</Data><Data Name='ProcessGuid'>{84453EAB-2FF8-5FCA-AF8D-DF0300000000}</Data><Data Name='ProcessId'>4860</Data><Data Name='Image'>C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='FileVersion'>6.1.7600.16385 (win7_rtm.090713-1255)</Data><Data Name='Description'>Windows PowerShell</Data><Data Name='Product'>Microsoft® Windows® Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noP -sta -w 1 -enc //5112bytes long payload//</Data><Data Name='CurrentDirectory'>C:\Users\IEuser\Downloads\</Data><Data Name='User'>WIN-40TITGP9BI7\IEuser</Data><Data Name='LogonGuid'>{84453EAB-6BA3-5FC6-A0CC-080000000000}</Data><Data Name='LogonId'>0x8cca0</Data><Data Name='TerminalSessionId'>2</Data><Data Name='IntegrityLevel'>Medium</Data><Data Name='Hashes'>MD5=92F44E405DB16AC55D97E3BFE3B132FA,SHA256=6C05E11399B7E3C8ED31BAE72014CF249C144A8F4A2C54A758EB2E6FAD47AEC7,IMPHASH=96BA691B035D05F44E35AB23F6BA946C</Data><Data Name='ParentProcessGuid'>{84453EAB-2FF8-5FCA-2680-DF0300000000}</Data><Data Name='ParentProcessId'>3700</Data><Data Name='ParentImage'>C:\Windows\SysWOW64\mshta.exe</Data><Data Name='ParentCommandLine'>"C:\Windows\SysWOW64\mshta.exe" "C:\Users\IEuser\Downloads\payload_hta.hta" </Data></EventData></Event>
```

##### Key Indicator

| Field        | Value                                                                                          | Comments |
| ------------ | ---------------------------------------------------------------------------------------------- | -------- |
| EventID      | 1                                                                                              |          |
| process_exec | powershell.exe                                                                                    |          |
| process_id   | 4860                                                                                           |          |
| parent_process_id   | 3700                                                                                           |          |
| cmdline      | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noP -sta -w 1 -enc //5112bytes long payload// |          |

Connect to C2
```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>11</EventID><Version>2</Version><Level>4</Level><Task>11</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2020-12-04T12:47:40.933507700Z'/><EventRecordID>23142</EventRecordID><Correlation/><Execution ProcessID='956' ThreadID='3828'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WIN-40TITGP9BI7</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='RuleName'>Downloads</Data><Data Name='UtcTime'>2020-12-04 12:47:40.933</Data><Data Name='ProcessGuid'>{84453EAB-2FBC-5FCA-9A1B-DD0300000000}</Data><Data Name='ProcessId'>4388</Data><Data Name='Image'>C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</Data><Data Name='TargetFilename'>C:\Users\IEuser\Downloads\f692e7e2-7146-4fd4-8778-e1f61201bde5.tmp</Data><Data Name='CreationUtcTime'>2020-12-04 12:47:40.933</Data></EventData></Event>
```
##### Key Indicator

| Field             | Value                                                                         | Comments |
| ----------------- | ----------------------------------------------------------------------------- | -------- |
| EventID           | 3                                                                             |          |
| process_exec      | powershell.exe                                                                |          |
| process_id   | 4860                                                                                           |          |
| dest_ip           | 192.168.254.46 | my test lab c2                                                     |
| dest_port         | 80             | depends on the empire listener type, in this simulation i set http |


## Reference 
https://www.fireeye.com/blog/threat-research/2018/04/metamorfo-campaign-targeting-brazilian-users.html
