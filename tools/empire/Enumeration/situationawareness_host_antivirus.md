# Situation Awareness - Antivirus

## Goal 
| Simulation # | Stager Option                           |
| ------------ | --------------------------------------- |
| 1            | usermodule situation_awareness/host/antivirusproduct |

## Technical Context
### Assumption
* Attacker is a low-priv user 
* The C2 connection has established 

### Simulation 1
This attack try to identify target's antivirus product

#### Payload Generation
```bash
(Empire: agents) > agents

[*] Active agents:

 Name     La Internal IP     Machine Name      Username                Process            PID    Delay    Last Seen            Listener
 ----     -- -----------     ------------      --------                -------            ---    -----    ---------            ----------------

 WMXUN8D2 ps 192.168.254.47  WIN-40TITGP9BI7   WIN-40TITGP9BI7\victim  powershell         920    1/0.0    2020-12-04 22:47:38  http
```
#### Attack Begin

1. Execute the enumeration module on empire

##### Raw Sysmon Event
nothing captured from sysmon

