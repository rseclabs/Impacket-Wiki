
title: "smbclient.py"
script: "examples/smbclient.py"
category: "SMB Tools"
status: "Published"
protocols:
  - SMB1
  - SMB2
  - SMB3
  - NetBIOS over TCP
ms_specs:
  - MS-CIFS
  - MS-SMB
  - MS-SMB2
  - MS-SRVS
mitre_techniques:
  - T1021.002
  - T1039
  - T1083
  - T1135
auth_types:
  - password
  - nt_hash
  - aes_key
  - kerberos_ccache
  - null_session
author_original: "Alberto Solino (@agsolino)"
first_appearance: "Mid 2000s"
tags:
  - impacket
  - impacket/examples
  - category/smb_tools
  - status/published
  - protocol/smb
  - protocol/netbios
  - protocol/msrpc
  - authentication/ntlm
  - authentication/kerberos
  - authentication/null_session
  - technique/enumeration
  - technique/file_access
  - mitre/T1021/002
  - mitre/T1039
  - mitre/T1083
  - mitre/T1135
aliases:
  - smbclient
  - impacket-smbclient


# smbclient.py

> **One line summary:** An interactive SMB client written in Python that lists shares, browses directories, and transfers files against Windows and Samba hosts using password, NT hash, AES key, or Kerberos ticket authentication.

| Field | Value |
|:---|:---|
| Script | `examples/smbclient.py` |
| Category | SMB Tools |
| Status | Published |
| Primary protocols | SMB1, SMB2, SMB3, NetBIOS over TCP |
| Primary Microsoft specifications | `[MS-CIFS]`, `[MS-SMB]`, `[MS-SMB2]`, `[MS-SRVS]` |
| MITRE ATT&CK techniques | T1021.002 SMB and Windows Admin Shares, T1039 Data from Network Shared Drive, T1083 File and Directory Discovery, T1135 Network Share Discovery |
| Authentication types supported | Cleartext password, NT hash, AES key, Kerberos ccache, NULL session |
| First appearance in Impacket | Mid 2000s |
| Original author | Alberto Solino (`@agsolino`) |



## What it does

`smbclient.py` is an interactive command shell that speaks SMB to a remote host. You run it, you get a prompt, and from that prompt you can enumerate the shares the server exposes, navigate into any share you have access to, list files, pull files down to your local machine, push files up, create and delete directories, and perform a handful of remote server operations such as listing active sessions or changing your own password. When you are done, you type `exit` and the shell closes the connection cleanly.

From a beginner's perspective, the easiest way to understand `smbclient.py` is to think of it as a file manager that operates over the network. You are not installing anything on the target. You are not opening a backdoor. You are using the same protocol a Windows workstation uses every day when a user clicks a mapped drive in File Explorer. The difference is that you are doing it from a Python script, on whatever operating system you happen to be on, with any of four different credential types, against targets that may or may not even be running Windows.

For a security researcher, that is exactly the value. Before you can attack a Windows environment intelligently, you have to see what is on it. Before you can defend one, you have to know what your servers are actually sharing. `smbclient.py` is the tool that lets you see. It is the Impacket equivalent of opening File Explorer and typing `\\server\share` in the address bar, except that it works from Linux, it accepts hashes and tickets, and every action you take is visible and scriptable.

This tool is also the starting point for learning the rest of Impacket. The class it builds on, `SMBConnection`, is used by roughly half of the other example tools. Learn how `smbclient.py` uses it and you have made significant progress on `psexec.py`, `secretsdump.py`, `smbexec.py`, `atexec.py`, and a dozen others.



## Why it exists

There is already a program called `smbclient` in the Samba project. It has existed since the 1990s, it is included in every Linux distribution, and it does many of the same things. So why does Impacket ship its own Python implementation?

Three reasons.

**Protocol coverage.** The Samba `smbclient` tracks Samba's own implementation of the protocol. For a long stretch it did not fully support SMB2 and SMB3 on the client side, or only supported them in awkward ways. Impacket's `smbclient.py` uses the same SMB2 and SMB3 implementation that the rest of Impacket uses, which is maintained to the Microsoft specifications.

**Authentication flexibility.** The Samba `smbclient` handles passwords and, with some help from a patched build, hashes. What it does not handle gracefully is Kerberos tickets stored in ccache files, AES keys as separate credentials, or the kind of no questions asked NULL session negotiation that a researcher often needs. Impacket treats all four credential types (password, hash, AES key, ccache) as first class inputs on the same command line.

**Python integration.** Because `smbclient.py` is Python all the way down, you can read its source, step through it in a debugger, modify it, or wholesale import its machinery into your own scripts. The `MiniImpacketShell` class is only a few hundred lines. Everything it knows how to do is something you can learn how to do.

The practical result is that a Linux or macOS operator can sit in front of any modern Windows environment and have a rich, scriptable SMB client without installing Samba, without patching anything, and without switching to a Windows box. For blue team analysts, the same is true. You can validate that a share really does require signing, that a given user really cannot read a sensitive directory, or that SMBv1 really is disabled, all from a Linux admin workstation.



## The protocol theory

To use `smbclient.py` well you need a mental model of SMB. The model does not have to be exhaustive. A few key ideas go a long way.

### SMB in one paragraph

Server Message Block is a file and printer sharing protocol invented at IBM in 1984 and extensively reworked by Microsoft over the following decades. It is the protocol behind every mapped drive, every `\\server\share\file.txt` path, and every Group Policy applied from a domain controller's `SYSVOL`. It also carries a lot of non file traffic, because Microsoft built many of its management protocols on top of SMB named pipes. Remote service control, remote registry editing, remote scheduled tasks, and a large fraction of Active Directory operations all ride on SMB underneath.

### Dialects: SMB1, SMB2, SMB3

The protocol has gone through three major generations.

- **SMB1** (originally CIFS) is the original. It is chatty, insecure by default, and has been deprecated by Microsoft for years. It is the dialect that was exploited by EternalBlue in 2017. Most modern networks have it disabled. Impacket can still speak it when necessary.
- **SMB2** introduced a cleaner message format, better performance, and optional signing. First shipped with Windows Vista.
- **SMB3** added pre authentication integrity, AES GCM encryption, and multichannel support. First shipped with Windows 8 and Windows Server 2012.

When an SMB client connects to a server, the first thing that happens is a **dialect negotiation**. The client sends a list of dialects it is willing to speak. The server picks the newest one both sides support. `smbclient.py` negotiates all the way up to SMB 3.1.1 by default.

### Ports

SMB traffic rides on two TCP ports historically.

- **Port 445** is direct SMB over TCP. This is what modern Windows uses. Almost every Impacket tool targets this port by default.
- **Port 139** is SMB wrapped in NetBIOS over TCP (NBT). This is the legacy path that predates port 445. If a target only exposes port 139, Impacket still works but the `smbclient.py` flag `-port 139` is needed.

### The SMB session lifecycle

Every SMB interaction follows the same sequence. Understanding it will make the output of a packet capture make sense.

1. **Negotiate Protocol.** Dialect negotiation.
2. **Session Setup.** Authentication happens here. The client proves who it is using NTLM or Kerberos. If successful, the server issues a session ID.
3. **Tree Connect.** The client connects to a specific share (for example, `\\server\C$`). The server responds with a tree ID that represents this specific share within this specific session.
4. **Create.** The client opens a specific file or directory within the tree. The server responds with a file ID.
5. **Read, Write, Query, Set.** Operations on the file.
6. **Close.** The file ID is released.
7. **Tree Disconnect** and **Logoff** end the session.

Every command in `smbclient.py` maps to one or more of these steps. When you type `use SYSVOL`, that is a Tree Connect. When you type `ls`, that is a Create on the directory, a Query Directory, and a Close. When you type `get file.txt`, that is Create, Read, Close.

### Administrative and hidden shares

Windows automatically creates several shares when a system is installed. They end in a dollar sign, which hides them from casual share browsers but not from `smbclient.py`.

| Share | Purpose |
|:---|:---|
| `ADMIN$` | The `C:\Windows` directory. Accessible to local administrators. Used heavily by remote execution tooling. |
| `C$`, `D$`, and so on | Root of each fixed local drive. Accessible to local administrators. |
| `IPC$` | The Inter Process Communication share. Carries SMB named pipes (`\pipe\samr`, `\pipe\lsarpc`, etc.). Accessible even on NULL sessions in some configurations. |
| `NETLOGON` | Present on domain controllers. Hosts logon scripts. Readable by any authenticated domain user. |
| `SYSVOL` | Present on domain controllers. Hosts Group Policy objects. Readable by any authenticated domain user. |

`NETLOGON` and `SYSVOL` are not hidden (no dollar sign). They are readable by any domain user and they contain fascinating data. `SYSVOL` in particular is where the `Get-GPPPassword.py` technique mines for cached credentials.

### NULL sessions

A NULL session is an SMB session authenticated as a blank user with a blank password. Legacy Windows versions allowed NULL sessions to enumerate users, groups, and shares. Modern Windows restricts what a NULL session can do, but misconfigured Samba shares and older systems still permit it. `smbclient.py` supports NULL sessions out of the box. No special flag, just leave the credentials empty.



## How the tool works internally

The script is short. If you have never opened an Impacket example before, this is a good one to read first. The whole thing is roughly the following flow.

1. **Argument parsing.** The `argparse` block defines the positional target argument and the authentication flags. Nothing here is Impacket specific.

2. **Target parsing.** The positional argument string (for example, `CORP/alice:S3cret@dc01.corp.local`) is passed to `impacket.examples.utils.parse_target`, which splits it into domain, username, password, and target host.

3. **Connection.** An `SMBConnection` instance is created, pointed at the target. This is the line that triggers SMB negotiation. By the time the constructor returns, the TCP socket is open, the SMB dialect has been negotiated, and the protocol stack on both sides has agreed to speak SMB2 or SMB3.

4. **Authentication.** Depending on which authentication flags were supplied, the tool calls one of `SMBConnection.login()`, `SMBConnection.loginWithHash()`, or `SMBConnection.kerberosLogin()`. Each of these is a wrapper around SMB session setup with a different credential type.

5. **Enter the shell.** The authenticated `SMBConnection` is handed to a class called `MiniImpacketShell`. This class inherits from Python's standard `cmd.Cmd`, which is the same module used by the Python debugger and many other interactive tools. Each method whose name starts with `do_` becomes a shell command. `do_ls` becomes `ls`, `do_shares` becomes `shares`, and so on.

6. **Each command maps to an SMB or RPC operation.** When you type `ls`, `do_ls` calls `listPath()` on the `SMBConnection`, which performs the Create, Query Directory, Close sequence described earlier. When you type `shares`, `do_shares` opens a DCERPC connection to the SRVSVC interface over the `\pipe\srvsvc` named pipe, calls `NetrShareEnum`, and formats the result. When you type `who`, the shell opens a connection to the TSTS interface and enumerates sessions. When you type `password`, the shell opens a SAMR connection over `\pipe\samr` and calls `SamrUnicodeChangePasswordUser2`.

The takeaway from this section is important for the rest of the wiki. `smbclient.py` is a demonstration of the basic pattern every other Impacket tool follows: **open an SMBConnection, authenticate, then layer MSRPC interfaces on top by opening named pipes through the existing SMB session.** Every tool that does remote execution, credential dumping, service control, or registry editing is some variation of that pattern. Once you see it in `smbclient.py`, you will see it everywhere.



## Authentication options

The four credential types are uniform across Impacket. Here is how each one looks for `smbclient.py`.

### Cleartext password

```bash
smbclient.py CORP/alice:'S3cret!'@dc01.corp.local
```

Put the password inline in the target string. Quote it if it contains shell special characters. The password is sent over NTLM or Kerberos during SMB session setup.

### NT hash

```bash
smbclient.py -hashes :aad3b435b51404eeaad3b435b51404ee8846f7eaee8fb117ad06bdd830b7586c \
  CORP/alice@dc01.corp.local
```

The format is `LMHASH:NTHASH`. Modern targets ignore the LM hash, so you will almost always see a blank value before the colon. This is the classic pass the hash flow. If all you have is an NT hash extracted from a memory dump or a registry hive, you can authenticate as that user without ever knowing their password.

### AES key

```bash
smbclient.py -aesKey <256 bit hex key> \
  CORP/alice@dc01.corp.local
```

A Kerberos AES key drawn from the same keying material Windows uses for AES256 or AES128 tickets. Produced by `secretsdump.py` against NTDS.dit. Used when the target network enforces AES only tickets, which some hardened environments do.

### Kerberos ccache

```bash
export KRB5CCNAME=/path/to/alice.ccache
smbclient.py -k -no-pass dc01.corp.local
```

The `-k` flag tells the tool to use Kerberos. The `-no-pass` flag says do not prompt for a password. The library reads the ticket from whatever ccache file the `KRB5CCNAME` environment variable points at. This is the mode used after a `getTGT.py` run, after a Kerberoast, or after obtaining a ticket through any other means.

### NULL session

```bash
smbclient.py @target.corp.local
```

Blank user, blank domain, blank password. The library attempts anonymous authentication. Works against misconfigured targets, legacy Samba, and some older Windows installations.

### The hierarchy inside the library

All four of the above land in one of three methods on `SMBConnection`:

- `login(user, password, domain, lmhash, nthash)` for NTLM with password or hash.
- `kerberosLogin(user, password, domain, lmhash, nthash, aesKey, kdcHost, TGT, TGS)` for Kerberos with any of password, hash, AES key, or existing ticket.
- `loginWithHash()` which is a thin convenience wrapper.

Understanding that the library lets you mix and match any input into Kerberos (password, hash, AES, ticket) is what makes the credential juggling in later articles like `getTGT.py` and `getST.py` easy to follow.



## Practical usage

A short tour of realistic scenarios.

### Connect and list shares

```text
$ smbclient.py CORP/alice:'S3cret!'@fs01.corp.local
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# shares
ADMIN$
C$
IPC$
Finance
HR
Marketing
Public
# use Public
# ls
drw-rw-rw-          0  Fri Jan 10 09:14:02 2025 .
drw-rw-rw-          0  Fri Jan 10 09:14:02 2025 ..
-rw-rw-rw-       4213  Wed Feb 05 13:22:01 2025 welcome.txt
drw-rw-rw-          0  Mon Mar 03 10:45:00 2025 templates
# cat welcome.txt
Welcome to the Public share. Please do not store sensitive data here.
#
```

### Pull a file down

```text
# use Finance
# cd Reports/2025
# ls
-rw-rw-rw-     128445  Fri Apr 04 08:12:33 2025 Q1_summary.xlsx
# get Q1_summary.xlsx
[*] Downloading: Q1_summary.xlsx
```

The file lands in the current local directory. If you want it somewhere else, change the local working directory first with `lcd`.

### Scripted invocation with a command file

Running an interactive shell inside an automated workflow is awkward. `smbclient.py` accepts a file of commands through `-file`.

```bash
cat > commands.txt <<'EOF'
use SYSVOL
cd corp.local/Policies
ls
exit
EOF

smbclient.py -file commands.txt CORP/alice:'S3cret!'@dc01.corp.local
```

The tool reads each line as if typed into the prompt and then exits.

### Enumerate SYSVOL on a domain controller

This is the textbook first move for a researcher with valid domain credentials.

```text
$ smbclient.py CORP/alice:'S3cret!'@dc01.corp.local
# use SYSVOL
# cd corp.local\Policies
# ls
# tree .
```

`SYSVOL` is readable by any authenticated domain user. Many environments store Group Policy Preference XML files there, which is the data source `Get-GPPPassword.py` mines for cached passwords. Getting comfortable with SMB navigation of `SYSVOL` is a prerequisite for that article.

### Check if SMB signing is required

Not directly a `smbclient.py` feature, but worth noting that you can enable verbose output with `-debug` and see the signing negotiation in the SMB2 negotiate response. For a dedicated signing check, most researchers reach for `CheckLDAPStatus.py` for LDAP or a short `nmap` script for SMB.

### Common mini shell commands

| Command | What it does |
|:---|:---|
| `shares` | Lists shares exposed by the target (runs `NetrShareEnum` over SRVSVC). |
| `use SHARE` | Connects to a specific share (SMB Tree Connect). |
| `ls` | Lists contents of the current directory. |
| `cd DIR` | Changes the current remote directory. |
| `lcd DIR` | Changes the local working directory. |
| `pwd` | Prints the current remote path. |
| `get FILE` | Downloads a file. |
| `put FILE` | Uploads a file. |
| `mget MASK` | Downloads multiple files matching a mask. |
| `cat FILE` | Prints a file to the terminal. |
| `mkdir DIR` | Creates a directory. |
| `rmdir DIR` | Removes an empty directory. |
| `rm FILE` | Deletes a file. |
| `rename SRC DST` | Renames a file. |
| `tree DIR` | Recursively lists a directory. |
| `info` | Returns `NetrServerInfo` details about the target. |
| `who` | Lists active sessions. Requires local administrator. |
| `password` | Changes the current user's password (requires knowing the current one). |
| `list_snapshots PATH` | Lists Volume Shadow Copy snapshots on the path. |
| `mount PATH SNAPSHOT` | Mounts a VSS snapshot. Useful for reading locked files. |
| `umount PATH` | Unmounts a VSS snapshot. |
| `login`, `kerberos_login`, `login_hash` | Reauthenticate without exiting the shell. |
| `logoff`, `close`, `exit` | End the session, close the tree, or quit. |



## What it looks like on the wire

Running `smbclient.py` against a target generates a predictable traffic pattern. Open Wireshark with an `smb2` display filter and you will see the following sequence in order.

1. **TCP handshake on port 445.** Three way SYN, SYN ACK, ACK.

2. **SMB2 Negotiate Protocol Request.** The client lists the dialects it supports (typically through SMB 3.1.1) and advertises what capabilities it has, including whether it can do signing and encryption. In SMB 3.1.1 this also includes the pre authentication integrity hash.

3. **SMB2 Negotiate Protocol Response.** The server picks a dialect and states whether signing and encryption are required. If signing is required, every subsequent message in this session will carry a message signature.

4. **SMB2 Session Setup Request.** This is where authentication happens. The payload carries either an NTLM challenge response or a Kerberos AP_REQ wrapped in SPNEGO. You can crack open this packet in Wireshark to see the username, the workstation name, and the challenge response material. In most networks the Session Setup is also the packet a hunting analyst is watching most closely.

5. **SMB2 Session Setup Response.** Contains the session ID and an SPNEGO reply confirming authentication succeeded.

6. **SMB2 Tree Connect Request** to `\\target\IPC$`. `smbclient.py` connects to `IPC$` by default when you run the `shares` command, because that is the share that hosts the SRVSVC named pipe.

7. **SMB2 Create Request** for `\srvsvc`. This is Impacket opening the named pipe.

8. **DCERPC Bind** on top of the Create response. The client declares it wants to use the SRVSVC interface.

9. **SRVSVC NetrShareEnum** call and response. This is what populates the output of the `shares` command.

10. **SMB2 Close**, **SMB2 Tree Disconnect**, and **SMB2 Logoff** when you type `exit`.

Two things to notice for a researcher learning the protocol for the first time.

**Everything important is visible.** The protocol is text in some places and binary in others, but it is almost never encrypted by default. A packet capture of a default Windows SMB session reveals the shares, the filenames, and often the file contents. This is also why SMB3 introduced optional encryption, and why some hardened environments require it.

**RPC rides inside SMB.** Notice that the `shares` command does not use a separate TCP connection for the SRVSVC RPC call. It rides on top of the existing SMB session, inside a Create on a named pipe. This is how every Impacket tool that uses RPC behaves. It is also why blocking port 445 at a network boundary also blocks every one of those tools.



## What it looks like in logs

On the target, a default Windows Server audit policy will write a handful of events for every `smbclient.py` session.

| Log | Event ID | Meaning | What to look at |
|:---|:---|||
| Security | 4624 | Successful logon | Logon Type 3 indicates a network logon. The `IpAddress` and `IpPort` fields identify the attacker. Workstation name in the event will usually be the Python host name unless the operator has set it explicitly. |
| Security | 4625 | Failed logon | Logged on wrong password or wrong username attempts. Repeated 4625s from the same source in a short window are a classic brute force indicator. |
| Security | 4672 | Special privileges assigned | Logged whenever an administrator logs on. If your `smbclient.py` session uses a privileged account, expect to see this. |
| Security | 4634 | Logoff | Logged when the SMB session ends. |
| Security | 5140 | Network share object was accessed | Logged when a Tree Connect succeeds. Contains the share name and the source IP. Often disabled by default. Enable it with "Audit Detailed File Share" policy. |
| Security | 5145 | Detailed file share | The gold standard for SMB forensics. Logs each file access attempt with the filename and the result. Noisy, but invaluable. Also requires "Audit Detailed File Share" to be enabled. |
| Security | 5142 / 5143 / 5144 | Share added / modified / deleted | Not relevant to pure reading, but worth knowing. |

Typical `smbclient.py` session leaves:

- One 4624 at session start.
- Zero or more 5140 events, one per Tree Connect (for each `use SHARE` command).
- Many 5145 events if detailed file auditing is on, one per `ls`, `get`, `put`, `cat`.
- One 4634 at session end.

On Windows itself, the operator side has its own artifacts. The `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` key is untouched because `smbclient.py` is not Explorer. No prefetch entries are written on the target, because `smbclient.py` is not executing anything on the target, only reading and writing files. That lack of execution trace is part of why operators reach for this tool over remote execution tools when they only need data.

Sysmon can add additional coverage. Sysmon Event ID 3 (Network connection) will log the outbound SMB traffic if Sysmon is running on the attacker's machine, and it will log the inbound connection if Sysmon is running on the target.



## Detection and defense

### Detection opportunities

The defender's challenge with `smbclient.py` is that it produces traffic that is, packet for packet, almost identical to a legitimate Windows client. The detections that work are behavioral rather than signature based.

**Unusual source.** A session originating from a non Windows operating system or an IP address that has never before talked SMB to this server. Analysts sometimes fingerprint the client by inspecting the User Agent style fields in the Session Setup, or by correlating with EDR data about processes on the source host.

**Unusual share access patterns.** One account reading every file in `SYSVOL`, then every file in `NETLOGON`, then poking at administrative shares, all within a minute, is not typical user behavior. Event ID 5145 is how you see this.

**Service accounts doing interactive work.** Service accounts almost never browse SMB shares by hand. A `svc_backup` account suddenly running `ls` style queries through many shares is worth an alert.

**Session Setup with unusual client workstation names.** Impacket does not set a meaningful workstation name by default. Defender tooling that looks at the `NTLMSSP` workstation field in Session Setup can spot the default. This is exploit specific and the operator can change it, so treat it as a hint, not a rule.

**Behavior versus intent.** Many environments allow authenticated users to read `SYSVOL`. That is by design. The interesting signal is not the single read. It is the combination of reads, the speed, and the identity doing them. Build detections that score those factors rather than alerting on any one of them.

A starting point for a Sigma style rule targeting enumeration of many shares in a short time period:

```yaml
title: SMB Share Enumeration Burst
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5140
  timeframe: 2m
  condition: selection | count(ShareName) by SubjectUserName, IpAddress > 8
level: medium
```

Tune the threshold to your environment. Eight distinct shares in two minutes is a reasonable starting point on a file server and probably too low on a domain controller where SYSVOL crawls are normal.

### Preventive controls

The fundamentals. None of these are new, but every one of them makes `smbclient.py` abuse harder and more visible.

- **Require SMB signing on servers.** SMB signing authenticates every message. It prevents NTLM relay over SMB, which is a separate but related class of attack. Signing is on by default for domain controllers and SMB3 encrypted shares.
- **Require SMB encryption where possible.** SMB 3.1.1 encryption turns the captures described above into opaque ciphertext. Combined with signing, it eliminates a significant piece of the observability problem for the attacker.
- **Disable SMBv1.** SMBv1 is legacy, insecure, and long since unnecessary. Windows servers have shipped with SMBv1 disabled since Windows Server 2019 by default. If it is still on, turn it off.
- **Turn on "Audit Detailed File Share."** Without this policy, events 5145 and friends do not fire. Most environments leave this off because it is noisy. Without it, SMB forensics is very limited. Consider tuning (exclude well known high volume paths) rather than disabling wholesale.
- **Constrain NULL sessions.** On modern Windows this is mostly handled by default, but confirm by setting `RestrictAnonymous` and `RestrictAnonymousSAM` to 1 on every system. Audit Samba servers as well.
- **Protect `SYSVOL`.** Remove Group Policy Preference XML files that contain encrypted passwords. Microsoft published the key in MS14-025 more than a decade ago. Any GPP password in `SYSVOL` today is a credential any domain user can harvest.
- **Monitor for Impacket style workstation names in NTLMSSP.** Detection engineering teams at Elastic, Splunk, and Microsoft have published rules targeting the default hostname that Impacket emits.
- **Apply least privilege to shares.** A finance user does not need read access to the HR share. An ordinary user does not need read access to an administrative share. Trim share ACLs aggressively. Most SMB reconnaissance is only interesting because so many shares are over permissioned.



## Related tools and attack chains

`smbclient.py` is a foundation tool. It appears in more attack chains than almost anything else in the toolkit.

- **[`Get-GPPPassword.py`](../01_recon_and_enumeration/Get_GPPPassword.md).** After confirming you can read `SYSVOL` with `smbclient.py`, this tool automates the extraction and decryption of any GPP password files it finds.
- **[`psexec.py`](../04_remote_execution/psexec.md), [`smbexec.py`](../04_remote_execution/smbexec.md), [`wmiexec.py`](../04_remote_execution/wmiexec.md).** All three open an SMBConnection exactly like `smbclient.py` does, and then layer remote execution on top. Reading `smbclient.py` first makes all three easier to understand.
- **[`secretsdump.py`](../03_credential_access/secretsdump.md).** Uses SMBConnection to reach the Remote Registry, Service Control Manager, and Directory Replication interfaces. The credential workflow is identical to what you just learned.
- **[`smbserver.py`](smbserver.md).** The server counterpart. If you understand what `smbclient.py` sends on the wire, `smbserver.py` is simply the other half of that conversation.
- **[`ntlmrelayx.py`](../06_relay_attacks/ntlmrelayx.md).** One of the things `ntlmrelayx.py` can do is relay an intercepted SMB authentication onward to another SMB target. Everything inside the relay client side is a variant of the SMBConnection setup that `smbclient.py` performs.
- **[`smbpasswd.py`](../07_ad_modification/smbpasswd.md) and [`changepasswd.py`](../07_ad_modification/changepasswd.md).** Both reuse the SMBConnection and SAMR pattern that the `password` command inside `smbclient.py` uses.

A typical early engagement workflow looks like this.

1. Start with low privilege domain credentials.
2. Run `smbclient.py CORP/low:pass@dc01` to enumerate shares visible to a normal user.
3. Navigate `SYSVOL` and `NETLOGON` for Group Policy data and logon scripts.
4. Pass those findings into `Get-GPPPassword.py` to check for cached credentials.
5. Pass found credentials into `secretsdump.py` to go deeper.
6. With dumped admin hashes, use `psexec.py` or `wmiexec.py` to move laterally.

Every arrow in that chain rests on what `smbclient.py` teaches you: how to open an SMB session, authenticate with whatever credential you currently hold, and read what the server is willing to show you.



## Further reading

- **`[MS-SMB2]`: Server Message Block (SMB) Protocol Versions 2 and 3.** The Microsoft specification. Long, but searchable, and the authoritative source for every SMB2 and SMB3 message format. Start at `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/`.
- **`[MS-CIFS]`: Common Internet File System (CIFS) Protocol.** Covers SMB1 for the few cases where it still matters.
- **`[MS-SRVS]`: Server Service Remote Protocol.** The RPC interface behind the `shares`, `who`, and `info` commands.
- **Microsoft's SMB hardening guidance.** `https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security` covers signing, encryption, and SMBv1 removal.
- **MITRE ATT&CK T1021.002** at `https://attack.mitre.org/techniques/T1021/002/` is the canonical entry for SMB based lateral movement.
- **Microsoft's auditing guidance for file shares.** `https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-detailed-file-share` explains how to enable and tune event 5145.
- **The Impacket source for `smbclient.py` and `MiniImpacketShell`.** Reading the code is the single best way to solidify everything above. The entire file is short enough to read in a sitting.
- **"SMB access from Linux" in the Samba wiki** is a useful counterpoint to Impacket, showing how the same protocol looks from the Samba implementation.

Every article from here forward assumes that you understand the SMB session lifecycle described above. If any part of it still feels abstract, run `smbclient.py` against a lab target, watch the traffic in Wireshark, and follow the Negotiate, Session Setup, Tree Connect, Create, Read, Close sequence for real. Thirty minutes in Wireshark is worth more than thirty pages of reading.
