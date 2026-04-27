```
 █████                                              █████                █████      
░░███                                              ░░███                ░░███       
 ░███  █████████████   ████████   ██████    ██████  ░███ █████  ██████  ███████     
 ░███ ░░███░░███░░███ ░░███░░███ ░░░░░███  ███░░███ ░███░░███  ███░░███░░░███░      
 ░███  ░███ ░███ ░███  ░███ ░███  ███████ ░███ ░░░  ░██████░  ░███████   ░███       
 ░███  ░███ ░███ ░███  ░███ ░███ ███░░███ ░███  ███ ░███░░███ ░███░░░    ░███ ███   
 █████ █████░███ █████ ░███████ ░░████████░░██████  ████ █████░░██████   ░░█████    
░░░░░ ░░░░░ ░░░ ░░░░░  ░███░░░   ░░░░░░░░  ░░░░░░  ░░░░ ░░░░░  ░░░░░░     ░░░░░     
                       ░███                                                         
                       █████                                                        
                      ░░░░░                                                         
                █████   ███   █████  ███  █████       ███                           
               ░░███   ░███  ░░███  ░░░  ░░███       ░░░                            
                ░███   ░███   ░███  ████  ░███ █████ ████                           
                ░███   ░███   ░███ ░░███  ░███░░███ ░░███                           
                ░░███  █████  ███   ░███  ░██████░   ░███                           
                 ░░░█████░█████░    ░███  ░███░░███  ░███                           
                   ░░███ ░░███      █████ ████ █████ █████                          
                    ░░░   ░░░      ░░░░░ ░░░░ ░░░░░ ░░░░░                           
                                                                                    
                                                                                    

```

A comprehensive protocol level reference for every example tool in the Fortra [Impacket](https://github.com/fortra/impacket) repository. This is NOT an official wiki from the maintainers at FORTRA. This is an independent work created to document the incredibly useful Impacket library. My motivation was to learn at a much deeper level how Impacket classes and the included example scripts work for my own pentesting work. I used AI to help put this together and made a large effort to make sure that all information is accurate and timely, so if you find an error, let me know.

Each article explains what the tool does, why it exists, the Microsoft specifications it rides on, how the code works internally, and what the tool looks like on the wire and in logs. The goal is that a reader who finishes any article could write their own version of the tool from scratch. However, you will not find the source code here. For that, you will need to go to: [https://github.com/fortra/impacket](https://github.com/fortra/impacket)

## How to navigate

- Articles are grouped into thirteen categories. Start in the category that matches your current task.
- Every article follows the same twelve section structure. Once you read one, you know the layout of all of them.
- Cross references live at the bottom of every article under **Related tools and attack chains**.

## Start here

- [**Impacket: Introduction and Architecture**](Introduction_and_Architecture.md). The prerequisite reading that orients every other article in the wiki. Covers what Impacket is, what it is trying to accomplish, how the library and tools relate, the stack from command line down to the wire, and a recommended reading path through the rest of the wiki.

## Categories and articles

### 01 Recon and Enumeration ✅

Tools that gather information about a target environment without changing state. Start here when you have initial credentials and need to understand the terrain.

- [`CheckLDAPStatus.py`](01_recon_and_enumeration/CheckLDAPStatus.md)
- [`DumpNTLMInfo.py`](01_recon_and_enumeration/DumpNTLMInfo.md)
- [`GetADComputers.py`](01_recon_and_enumeration/GetADComputers.md)
- [`GetADUsers.py`](01_recon_and_enumeration/GetADUsers.md)
- [`GetLAPSPassword.py`](01_recon_and_enumeration/GetLAPSPassword.md)
- [`GetNPUsers.py`](01_recon_and_enumeration/GetNPUsers.md)
- [`GetUserSPNs.py`](01_recon_and_enumeration/GetUserSPNs.md)
- [`Get-GPPPassword.py`](01_recon_and_enumeration/Get_GPPPassword.md)
- [`findDelegation.py`](01_recon_and_enumeration/findDelegation.md)
- [`getArch.py`](01_recon_and_enumeration/getArch.md)
- [`lookupsid.py`](01_recon_and_enumeration/lookupsid.md)
- [`machine_role.py`](01_recon_and_enumeration/machine_role.md)
- [`net.py`](01_recon_and_enumeration/net.md)
- [`netview.py`](01_recon_and_enumeration/netview.md)
- [`rpcdump.py`](01_recon_and_enumeration/rpcdump.md)
- [`rpcmap.py`](01_recon_and_enumeration/rpcmap.md)
- [`samrdump.py`](01_recon_and_enumeration/samrdump.md)

### 02 Kerberos Attacks ✅

Tools that request, forge, or manipulate Kerberos tickets. The Kerberos section assumes the reader has read the [`getTGT.py`](02_kerberos_attacks/getTGT.md) article first. Note: `goldenPac.py` is a Kerberos attack but is categorized under [11 Exploits](#11-exploits) because it is first and foremost an exploit for CVE-2014-6324.

- [`getPac.py`](02_kerberos_attacks/getPac.md)
- [`getST.py`](02_kerberos_attacks/getST.md)
- [`getTGT.py`](02_kerberos_attacks/getTGT.md)
- [`keylistattack.py`](02_kerberos_attacks/keylistattack.md)
- [`kintercept.py`](02_kerberos_attacks/kintercept.md)
- [`raiseChild.py`](02_kerberos_attacks/raiseChild.md)
- [`ticketConverter.py`](02_kerberos_attacks/ticketConverter.md)
- [`ticketer.py`](02_kerberos_attacks/ticketer.md)

### 03 Credential Access ✅

Tools that extract credentials from a target. Short section, heavy content.

- [`dpapi.py`](03_credential_access/dpapi.md)
- [`mimikatz.py`](03_credential_access/mimikatz.md)
- [`secretsdump.py`](03_credential_access/secretsdump.md)

### 04 Remote Execution ✅

Tools that run commands on a target machine. Each uses a different Windows mechanism. Compare them side by side when choosing one for an engagement.

- [`atexec.py`](04_remote_execution/atexec.md)
- [`dcomexec.py`](04_remote_execution/dcomexec.md)
- [`psexec.py`](04_remote_execution/psexec.md)
- [`smbexec.py`](04_remote_execution/smbexec.md)
- [`wmiexec.py`](04_remote_execution/wmiexec.md)
- [`wmipersist.py`](04_remote_execution/wmipersist.md)
- [`wmiquery.py`](04_remote_execution/wmiquery.md)

### 05 SMB Tools ✅

SMB client and server utilities. Transfer files, stand up a server, or capture hashes.

- [`karmaSMB.py`](05_smb_tools/karmaSMB.md)
- [`smbclient.py`](05_smb_tools/smbclient.md)
- [`smbserver.py`](05_smb_tools/smbserver.md)

### 06 Relay Attacks ✅

NTLM relay tooling. Essential reading for flat Windows networks.

- [`ntlmrelayx.py`](06_relay_attacks/ntlmrelayx.md)

### 07 AD Modification ✅

Tools that write to Active Directory rather than read from it. Handle these in authorized engagements only. Each tool writes a specific attribute or permission.

- [`addcomputer.py`](07_ad_modification/addcomputer.md)
- [`badsuccessor.py`](07_ad_modification/badsuccessor.md)
- [`changepasswd.py`](07_ad_modification/changepasswd.md)
- [`dacledit.py`](07_ad_modification/dacledit.md)
- [`owneredit.py`](07_ad_modification/owneredit.md)
- [`rbcd.py`](07_ad_modification/rbcd.md)
- [`smbpasswd.py`](07_ad_modification/smbpasswd.md)

### 08 Remote System Interaction ✅

Tools that touch a remote system without necessarily executing arbitrary commands. Service management, registry edits, terminal sessions.

- [`attrib.py`](08_remote_system_interaction/attrib.md)
- [`rdp_check.py`](08_remote_system_interaction/rdp_check.md)
- [`reg.py`](08_remote_system_interaction/reg.md)
- [`services.py`](08_remote_system_interaction/services.md)
- [`tstool.py`](08_remote_system_interaction/tstool.md)

### 09 MSSQL ✅

Microsoft SQL Server client and discovery tools.

- [`checkMSSQLStatus.py`](09_mssql/checkMSSQLStatus.md)
- [`mssqlclient.py`](09_mssql/mssqlclient.md)
- [`mssqlinstance.py`](09_mssql/mssqlinstance.md)

### 10 Exchange ✅

Microsoft Exchange client and abuse tooling.

- [`exchanger.py`](10_exchange/exchanger.md)

### 11 Exploits ✅

One off exploit modules shipped alongside the protocol tools.

- [`sambaPipe.py`](11_exploits/sambaPipe.md)

### 12 Network Analysis ✅

Packet construction, sniffing, and auxiliary network tooling. These are the reference examples that show how Impacket builds and parses frames.

- [`mqtt_check.py`](12_network_analysis/mqtt_check.md)
- [`nmapAnswerMachine.py`](12_network_analysis/nmapAnswerMachine.md)
- [`ping.py`](12_network_analysis/ping.md)
- [`ping6.py`](12_network_analysis/ping6.md)
- [`sniff.py`](12_network_analysis/sniff.md)
- [`sniffer.py`](12_network_analysis/sniffer.md)
- [`split.py`](12_network_analysis/split.md)

### 13 File Format Parsing ✅

Offline file format parsers. Essential for working with disk captured artifacts such as NTDS.dit exports, raw NTFS images, and registry hives.

- [`esentutl.py`](13_file_format_parsing/esentutl.md)
- [`ntfs-read.py`](13_file_format_parsing/ntfs_read.md)
- [`registry-read.py`](13_file_format_parsing/registry_read.md)


## Suggested reading paths

**New to Active Directory attack tooling.** Read in order: `smbclient.py`, `rpcdump.py`, `samrdump.py`, `GetUserSPNs.py`, `GetNPUsers.py`, `getTGT.py`, `secretsdump.py`, `psexec.py`.

**Focused on Kerberos.** Read in order: `getTGT.py`, `getST.py`, `ticketer.py`, `ticketConverter.py`, `getPac.py`, `raiseChild.py`, `keylistattack.py`, `kintercept.py`. Then read `goldenPac.py` in the Exploits category for the historical CVE-2014-6324 attack.

**Focused on relay attacks.** Read in order: `ntlmrelayx.py`, `karmaSMB.py`, `smbserver.py`.

**Focused on detection engineering.** Read every article's section 9 and 10 in sequence. The cross cutting event ID reference in `_MEMORY.md` applies.

**Curious about the wire.** Read in order: `ping.py`, `sniff.py`, `rpcdump.py`, `smbclient.py`, `psexec.py`. These move from raw packets up through MSRPC up through full remote execution.

## Licensing and attribution

This wiki is an independent educational resource. Impacket itself is maintained by Fortra under a modified Apache Software License. Credit to the original Impacket authors, especially Alberto Solino (`@agsolino`), and to the wider community of contributors whose research made these tools possible.

## Status

This is a living document. Expect regular additions and revisions.
