
title: "samrdump.py"
script: "examples/samrdump.py"
category: "Recon and Enumeration"
status: "Published"
protocols:
  - MSRPC
  - SMB
  - MS-SAMR
ms_specs:
  - MS-SAMR
  - MS-RPCE
mitre_techniques:
  - T1087.001
  - T1087.002
  - T1069.001
  - T1069.002
  - T1033
auth_types:
  - password
  - nt_hash
  - aes_key
  - kerberos_ccache
  - null_session
tags:
  - impacket
  - impacket/examples
  - category/recon_and_enumeration
  - status/published
  - protocol/msrpc
  - protocol/samr
  - protocol/smb
  - authentication/ntlm
  - authentication/kerberos
  - authentication/null_session
  - technique/enumeration
  - technique/account_discovery
  - mitre/T1087/001
  - mitre/T1087/002
  - mitre/T1069/001
  - mitre/T1069/002
  - mitre/T1033
aliases:
  - samrdump
  - impacket-samrdump


# samrdump.py

> **One line summary:** Uses the MS-SAMR protocol to enumerate local and domain user accounts on a Windows target, returning names, RIDs, account control flags, logon timestamps, and password related metadata for every account the caller is allowed to see.

| Field | Value |
|:---|:---|
| Script | `examples/samrdump.py` |
| Category | Recon and Enumeration |
| Status | Published |
| Primary protocols | MSRPC, SMB, MS-SAMR |
| Primary Microsoft specifications | `[MS-SAMR]`, `[MS-RPCE]` |
| MITRE ATT&CK techniques | T1087.001 Local Account Discovery, T1087.002 Domain Account Discovery, T1069.001 Local Groups, T1069.002 Domain Groups, T1033 System Owner/User Discovery |
| Authentication types supported | Password, NT hash, AES key, Kerberos ccache, NULL session (legacy targets) |
| First appearance in Impacket | Very early (one of the original example tools) |
| Original authors | Javier Kohen, Alberto Solino (`@agsolino`) |



## Prerequisites

This article assumes you have already read:

- [`00_Introduction_and_Architecture.md`](Introduction_and_Architecture.md) for the Impacket stack overview.
- [`smbclient.py`](../05_smb_tools/smbclient.md) for the SMB session lifecycle and the four authentication modes (password, NT hash, AES key, Kerberos ccache).
- [`rpcdump.py`](rpcdump.md) for DCE/RPC, interface UUIDs, string bindings, and the endpoint mapper. The UUID for SAMR (`12345778-1234-abcd-ef00-0123456789ac`) appears in that article's reference table.

Nothing in this article re explains those foundations. If something below feels unfamiliar, the prior articles are where to fill the gap.



## What it does

`samrdump.py` connects to the Security Account Manager Remote protocol on a target Windows host and walks its account database. The output is a list of every user account the caller has permission to see, with full metadata: the username, the Relative Identifier (RID) that uniquely identifies the account inside its domain, account control flags that describe whether the account is enabled, whether it can be used for smart card logon, whether its password never expires, and whether it has other special attributes, plus timestamps for last logon, last password set, last bad password attempt, and account expiration.

Against a workstation or member server, `samrdump.py` enumerates the **local** SAM database: local accounts like `Administrator`, `Guest`, and any locally defined service accounts.

Against a **domain controller**, `samrdump.py` enumerates the domain account database: every user in Active Directory that the caller has read access to.

The tool does not modify anything. It is purely a read operation. That is why it appears in the Recon and Enumeration category rather than the AD Modification category, and it is why it often works with credentials that are nowhere near administrative.

For a security researcher this is one of the fastest ways to translate a valid domain credential into an account map of the entire environment. For a defender it is the single clearest demonstration that a low privilege user can learn a surprising amount about the domain, which is why modern hardening focuses on restricting what authenticated users can query from SAMR.



## Why it exists

The Security Account Manager Remote protocol has been part of Windows since Windows NT 3.1. It was designed to support legitimate tools like `User Manager for Domains` and the various `net user` commands, all of which needed to read and write the user database on remote systems. The protocol was defined before the Active Directory era, and it still works exactly as it did in 1993.

When SAMR first shipped, it allowed **anonymous** enumeration by default. A remote caller with no credentials at all could open the SAMR named pipe, connect to the SAM server, and walk the account list. Defaults on early Windows NT installations did not restrict this. Countless reconnaissance workflows from the late 1990s and early 2000s relied on it.

Microsoft began restricting anonymous SAMR access in the Windows 2000 era, first by introducing the `RestrictAnonymous` registry value and eventually by locking the default behavior down to authenticated callers only. Modern Windows installations will refuse an anonymous SAMR connection out of the box. The tool still tries, because legacy environments and misconfigured Samba servers sometimes still allow it, and because the defaults in some jurisdictions or industries have been deliberately relaxed.

Once authenticated SAMR enumeration became the norm, the protocol retained its value for attackers and auditors alike because Active Directory does not hide the account list from ordinary domain users. Any authenticated user can query SAMR to see every other account in the domain. This is a deliberate design trade off on Microsoft's part: discovery has to work for legitimate clients, and fine grained ACLs on account existence would break too many things. The practical consequence is that a single valid domain credential, even one belonging to a help desk intern, is enough to enumerate the entire workforce.

`samrdump.py` exists as a compact demonstration of the protocol. It is the Impacket version of the SAMR calls that tools like `net user /domain`, `User Manager`, `BloodHound`, and a dozen other enumeration frameworks all rely on.



## The protocol theory

Everything in this section assumes the foundations from [`rpcdump.py`](rpcdump.md) are already in place. SAMR is one of many MSRPC interfaces. Its bindings, its UUID, and its general mechanics follow the conventions described there.

What is new here is specific to SAMR.

### The SAM database

On a Windows system the Security Account Manager is a named database that stores local accounts. Its on disk form is a registry hive at `HKLM\SAM`, which corresponds to the file `%SystemRoot%\System32\config\SAM`. The hive contains user records, group records, password hashes, and security descriptors. On a domain controller the story is richer: the SAM database is augmented by the Active Directory database file `NTDS.dit`, and SAMR calls that would read local account data on a workstation instead read the AD account data. The protocol does not change. The underlying storage does.

When `samrdump.py` connects to a target, it is connecting to whichever SAM database that target exposes. A workstation exposes its local SAM. A domain controller exposes the domain SAM.

### MS-SAMR

The Microsoft specification for this interface is `[MS-SAMR]`: Security Account Manager Remote Protocol. It is one of the longer specifications because SAMR exposes operations for reading, creating, modifying, and deleting accounts, groups, and aliases. `samrdump.py` uses only a small slice of the protocol: the read operations that enumerate the database.

The interface UUID is `12345778-1234-abcd-ef00-0123456789ac`, version 1.0. The default binding is the SMB named pipe `\pipe\samr` on port 445, which means every SAMR call rides inside an authenticated SMB session. Direct TCP bindings exist too but are less common in the wild.

### The handle based object model

SAMR is built around **handles**. You do not call a generic `list_users` function. Instead you walk a small tree of objects, opening a handle to each one as you go.

The tree looks like this:

```
SAM server (one per target host)
├── Domain: "Builtin"       ← the built in alias domain
│   ├── Aliases (local groups)
│   └── Members
├── Domain: "TEST"          ← the workgroup or NetBIOS domain
│   ├── Users
│   ├── Groups
│   └── Aliases
└── Domain: <...>           ← additional domains on a trusted forest
```

Every object in the tree is reached by opening a handle to the object above it. A call returns a handle, you pass that handle into the next call, and so on. At the end you close each handle explicitly to free server side resources.

### The specific calls samrdump.py uses

The tool makes a fixed sequence of calls against this object model. You will see the same sequence in `net.py`, in `smbpasswd.py`, in `addcomputer.py`, and in many of the Active Directory modification tools in this wiki. Learning it once pays off repeatedly.

| Call | Purpose |
|:---|:---|
| `SamrConnect` | Opens a handle to the SAM server itself. Returns a server handle. |
| `SamrEnumerateDomainsInSamServer` | Lists every domain the server knows about. On a workstation this typically returns `Builtin` and the computer's workgroup name. On a domain controller this returns `Builtin` and the AD domain NetBIOS name. |
| `SamrLookupDomainInSamServer` | Converts a domain name into a domain SID. |
| `SamrOpenDomain` | Opens a handle to a specific domain, given its SID. Returns a domain handle. |
| `SamrEnumerateUsersInDomain` | Returns a paginated list of user accounts inside that domain. Each entry carries a username and a RID. |
| `SamrOpenUser` | Opens a handle to a specific user, given its RID. Returns a user handle. |
| `SamrQueryInformationUser2` | Reads a block of information about that user. The content depends on the "information class" the caller requests. |
| `SamrCloseHandle` | Closes a handle. Called at every level as the tool unwinds. |

The tool uses `UserAllInformation` as its information class when calling `SamrQueryInformationUser2`. This is the richest read level. The response contains the username, full name, UserAccountControl flags, password last set time, last logon time, last logoff time, account expires time, primary group ID, logon hours, and more.

### Helper functions in Impacket

Reading `samrdump.py` source you will see calls prefixed with a lowercase `h`, such as `hSamrConnect`, `hSamrEnumerateUsersInDomain`, and `hSamrOpenDomain`. These are **helper wrappers** in `impacket.dcerpc.v5.samr` that accept simple Python arguments, build the correct request structure, send it through the DCERPC transport, and return the response. The underlying raw RPC calls without the `h` prefix also exist in the module, but the helpers are what tools should use. This `h*` convention applies across the entire Impacket DCERPC library. Every interface in `impacket.dcerpc.v5` (SAMR, LSAD, SCMR, TSCH, RRP, DRSUAPI, and the rest) exposes the same helper pattern.

### RIDs and SIDs

One more idea worth pinning down before reading the output.

A **SID** (Security Identifier) is a unique identifier for a security principal. Domain SIDs look like `S-1-5-21-<random1>-<random2>-<random3>`, with three randomly generated 32 bit numbers that were chosen when the domain was created.

A **RID** (Relative Identifier) is the last piece of a SID, appended to the domain SID to form the full account SID. A user with RID 1105 in a domain whose SID is `S-1-5-21-1170647656-860703057-891382899` has the full SID `S-1-5-21-1170647656-860703057-891382899-1105`.

Certain RIDs are well known and always mean the same thing:

| RID | Meaning |
|:---|:---|
| 500 | Built in Administrator account |
| 501 | Built in Guest account |
| 502 | KRBTGT account (Kerberos service on DCs) |
| 512 | Domain Admins group |
| 513 | Domain Users group |
| 514 | Domain Guests group |
| 515 | Domain Computers group |
| 516 | Domain Controllers group |
| 519 | Enterprise Admins group |
| 520 | Group Policy Creator Owners |
| 544 | Built in Administrators local group (inside the `Builtin` domain) |
| 545 | Built in Users local group |

Every new account created in a domain receives a RID starting at 1000 or 1104, depending on the Windows version. `samrdump.py` prints RIDs with every account, which means you can tell at a glance which accounts are old and which are new, and which accounts are the built in privileged ones.

### UserAccountControl flags

The `UserAccountControl` field returned by `SamrQueryInformationUser2` is a 32 bit bitmask that describes every stateful attribute of the account. Learning to read UAC flags makes `samrdump.py` output dramatically more useful.

| Flag | Value (hex) | Meaning |
|:---|:---||
| `SCRIPT` | `0x0001` | Logon script will be executed |
| `ACCOUNTDISABLE` | `0x0002` | The account is disabled |
| `LOCKOUT` | `0x0010` | The account is currently locked out |
| `PASSWD_NOTREQD` | `0x0020` | The account does not require a password |
| `PASSWD_CANT_CHANGE` | `0x0040` | The user cannot change their password |
| `ENCRYPTED_TEXT_PWD_ALLOWED` | `0x0080` | Reversible encryption enabled (very bad) |
| `NORMAL_ACCOUNT` | `0x0200` | Standard user account |
| `INTERDOMAIN_TRUST_ACCOUNT` | `0x0800` | Trust account for another domain |
| `WORKSTATION_TRUST_ACCOUNT` | `0x1000` | Computer account |
| `SERVER_TRUST_ACCOUNT` | `0x2000` | Domain controller computer account |
| `DONT_EXPIRE_PASSWORD` | `0x10000` | Password never expires |
| `SMARTCARD_REQUIRED` | `0x40000` | Smart card required for logon |
| `TRUSTED_FOR_DELEGATION` | `0x80000` | Unconstrained delegation enabled |
| `NOT_DELEGATED` | `0x100000` | Account is marked sensitive |
| `USE_DES_KEY_ONLY` | `0x200000` | Only DES keys for Kerberos (legacy) |
| `DONT_REQUIRE_PREAUTH` | `0x400000` | Kerberos preauth not required (AS-REP roastable) |
| `PASSWORD_EXPIRED` | `0x800000` | The password has expired |
| `TRUSTED_TO_AUTH_FOR_DELEGATION` | `0x1000000` | Constrained delegation with protocol transition |

Two of these flags are attacker catnip and should jump out whenever you see them in output:

- `DONT_REQUIRE_PREAUTH` (`0x400000`) identifies accounts vulnerable to [AS-REP Roasting](GetNPUsers.md).
- `TRUSTED_FOR_DELEGATION` (`0x80000`) identifies accounts trusted for unconstrained delegation, which are historically high value compromise targets.

`samrdump.py` does not decode these flags into human labels in its default output. It prints the raw hex value. Translating the value using the table above is where the real information lives.



## How the tool works internally

The script's flow is short and it maps directly to the protocol walk described above.

1. **Argument parsing and credential extraction.** Same pattern covered in the prior articles. The tool accepts the standard `target` positional argument, `-hashes`, `-aesKey`, `-k`, `-no-pass`, `-dc-ip`, `-target-ip`, `-port`, and a `-csv` flag that changes the output format.

2. **Endpoint discovery.** Before binding to SAMR directly, the tool performs an `ept_lookup` against the endpoint mapper to learn where SAMR is listening. This is why the first line of output reads `[*] Retrieving endpoint list from <target>`. If the endpoint mapper lookup succeeds the tool uses the discovered binding. If it fails the tool falls back to the default named pipe binding `\pipe\samr` on port 445.

3. **SMB session establishment.** Authentication is performed through the same `SMBConnection` facade used by every SMB based Impacket tool. See [`smbclient.py`](../05_smb_tools/smbclient.md) for the session lifecycle.

4. **DCERPC bind to SAMR.** The tool opens the `\pipe\samr` named pipe inside the SMB session, issues a DCERPC Bind for UUID `12345778-1234-abcd-ef00-0123456789ac`, and receives a bind acknowledgment.

5. **`SamrConnect`.** Produces the server handle. The caller's access rights on that handle determine what follows can and cannot do.

6. **`SamrEnumerateDomainsInSamServer`.** Returns the list of domains. On a workstation you typically see `Builtin` and the machine name. On a domain controller you see `Builtin` and the NetBIOS domain name.

7. **For each returned domain:**
    - `SamrLookupDomainInSamServer` converts the domain name to a SID.
    - `SamrOpenDomain` opens a handle to that domain.
    - `SamrEnumerateUsersInDomain` walks the user list, paginated by an `enumerationContext` cursor.
    - For each user, `SamrOpenUser` gets a user handle and `SamrQueryInformationUser2` fills in the `UserAllInformation` block.
    - Results are formatted to the console or to CSV.
    - Handles are closed cleanly at each level.

8. **Shutdown.** `SamrCloseHandle` is called on the server handle. The DCERPC session ends. The SMB session is torn down. The TCP socket closes.

A close reading of the script reveals a few small subtleties worth noticing. The tool uses `MAXIMUM_ALLOWED` as the access mask on handle opens, which asks the server for every right the caller is entitled to. This is common in Impacket and is usually fine, but it can surface event log entries about high privilege access requests that a more conservative client would not produce.



## Authentication options

The four standard credential types all apply. SAMR rides on an SMB session, so the authentication follows the same pattern as [`smbclient.py`](../05_smb_tools/smbclient.md).

### Cleartext password

```bash
samrdump.py CORP/alice:'S3cret!'@dc01.corp.local
```

### NT hash

```bash
samrdump.py -hashes :<nthash> CORP/alice@dc01.corp.local
```

### AES key

```bash
samrdump.py -aesKey <256 bit hex key> CORP/alice@dc01.corp.local
```

### Kerberos ccache

```bash
export KRB5CCNAME=/path/to/alice.ccache
samrdump.py -k -no-pass CORP/alice@dc01.corp.local
```

### NULL session

```bash
samrdump.py @target.corp.local
```

A NULL session will fail on any reasonably modern Windows installation. It is still worth attempting during an engagement because misconfigured Samba servers and legacy Windows hosts sometimes still permit it. When it works, it means the target has been configured below the current Microsoft default. That finding in itself is worth reporting.

### A note on the minimum privilege needed

SAMR enumeration succeeds with ordinary authenticated user credentials against a domain controller. You do not need to be a domain admin. You do not need to be a local admin on the DC. A single valid domain account with a password you know is enough to walk the entire user list.

Against a workstation the same rule applies: ordinary authenticated access is enough to enumerate local accounts, because the machine account handshake that establishes the SMB session also satisfies SAMR's access checks. The practical effect is that any domain joined machine exposes its local account list to any authenticated domain user.



## Practical usage

### Enumerate a domain controller's account list

```text
$ samrdump.py CORP/alice:'S3cret!'@dc01.corp.local
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Retrieving endpoint list from dc01.corp.local
[*] Trying protocol 445/SMB...
Found domain(s):
 . CORP
 . Builtin
[*] Looking up users in domain CORP
Found user: Administrator, uid = 500
Found user: Guest, uid = 501
Found user: krbtgt, uid = 502
Found user: svc_sql, uid = 1104
Found user: svc_backup, uid = 1105
Found user: alice, uid = 1106
Found user: bob, uid = 1107
Found user: charlie, uid = 1108
Found user: svc_roastme, uid = 1109
...

Administrator (500)/Enabled: true
Administrator (500)/Last Logon: 2026-04-18 08:14:32
Administrator (500)/Last Logoff: <never>
Administrator (500)/Account Expires: <never>
Administrator (500)/Password last set: 2026-01-10 11:22:03
Administrator (500)/Password does not expire: true
Administrator (500)/UserAccountControl: 0x10200
Administrator (500)/Bad password count: 0
Administrator (500)/Logon count: 427
...

svc_roastme (1109)/Enabled: true
svc_roastme (1109)/Password last set: 2024-06-03 14:02:51
svc_roastme (1109)/UserAccountControl: 0x410200
svc_roastme (1109)/Logon count: 0
...
```

Two things to notice in that output.

The `Administrator` account's UAC is `0x10200`, which decodes to `NORMAL_ACCOUNT` (`0x200`) plus `DONT_EXPIRE_PASSWORD` (`0x10000`). A domain Administrator with a password that never expires is common but worth flagging.

The `svc_roastme` account's UAC is `0x410200`, which decodes to `NORMAL_ACCOUNT` plus `DONT_EXPIRE_PASSWORD` plus `DONT_REQUIRE_PREAUTH` (`0x400000`). That third flag is the big one. `DONT_REQUIRE_PREAUTH` means the account is vulnerable to AS-REP Roasting and can be targeted with [`GetNPUsers.py`](GetNPUsers.md). Attacker or defender, this is exactly the kind of finding `samrdump.py` is built to surface.

### CSV output for analysis

When working across large domains it is easier to move the data into a spreadsheet or a SIEM. The `-csv` flag produces a comma separated form suitable for import.

```bash
samrdump.py -csv CORP/alice:'S3cret!'@dc01.corp.local > corp_users.csv
```

Each line becomes a full account record. Sort by password last set date to find stale accounts. Filter on a UAC mask to find accounts vulnerable to preauth roasting. Both are one line operations once the data is in CSV form.

### Enumerate a workstation's local SAM

```bash
samrdump.py CORP/alice:'S3cret!'@ws01.corp.local
```

Against a workstation the `Found domain(s)` list will show `Builtin` and the workstation's own computer name. Users inside the workstation's own domain are local accounts. Users inside the `Builtin` domain are local groups such as `Administrators` and `Users`. `samrdump.py` enumerates users in both domains.

### A non domain test

Against a standalone Windows host with a known local account:

```bash
samrdump.py -port 445 ./testuser:'Password1'@10.0.0.50
```

The `./` prefix indicates a blank domain, meaning local authentication rather than domain. Useful against workgroup systems.

### Key flags

| Flag | Meaning |
|:---|:---|
| `-hashes LMHASH:NTHASH` | NT hash authentication |
| `-aesKey <hex>` | Kerberos AES key |
| `-k` | Use Kerberos from a ccache file |
| `-no-pass` | Do not prompt for a password, paired with `-k` |
| `-dc-ip <ip>` | Explicit domain controller IP for Kerberos |
| `-target-ip <ip>` | Explicit target IP if name resolution fails |
| `-port <135\|139\|445>` | Alternative transport port |
| `-csv` | CSV output instead of human readable |
| `-debug` | Full protocol trace on stderr |
| `-ts` | Prepend a timestamp to every log line |



## What it looks like on the wire

The full packet sequence against a modern target is a fusion of SMB, MSRPC, and SAMR. Each layer was covered in prior articles, so this section focuses on the SAMR specific parts.

For the SMB setup through Tree Connect to `IPC$`, see the wire walkthrough in [`smbclient.py`](../05_smb_tools/smbclient.md).

For the DCERPC Bind and endpoint mapper discovery, see the wire walkthrough in [`rpcdump.py`](rpcdump.md).

Once the SMB session is authenticated and the `\pipe\samr` named pipe is open with a DCERPC Bind acknowledged for the SAMR UUID, the SAMR specific traffic looks like this in Wireshark with the `samr` display filter active.

1. **SAMR `Connect` Request / Response.** Establishes the server handle.

2. **SAMR `EnumerateDomainsInSamServer` Request / Response.** Returns a list of domain names as Unicode strings.

3. **SAMR `LookupDomainInSamServer` Request / Response.** Converts a domain name to a SID. The response contains the SID bytes.

4. **SAMR `OpenDomain` Request / Response.** Returns the domain handle.

5. **Batch of SAMR `EnumerateUsersInDomain` calls.** Each response carries a block of `(RID, Unicode username)` pairs plus an `enumerationContext` that points at the next batch. The tool keeps calling until the server signals the list is complete.

6. **For each discovered user:**
    - SAMR `OpenUser` Request / Response.
    - SAMR `QueryInformationUser2` Request for `UserAllInformation`.
    - SAMR `QueryInformationUser2` Response. The response carries a large structure with the username, timestamps, flags, and so on.
    - SAMR `CloseHandle` on the user handle.

7. **SAMR `CloseHandle` calls** for each domain handle and then the server handle.

In Wireshark, applying the filter `samr.opnum` and looking at the Info column lets you read the sequence of opnums at a glance. The pattern is unmistakable: `Connect`, `EnumerateDomainsInSamServer`, `LookupDomainInSamServer`, `OpenDomain`, repeated `EnumerateUsersInDomain`, then a tight loop of `OpenUser` and `QueryInformationUser2` for each user.

If encryption or signing is negotiated during the SMB session (the default on modern Windows), the SAMR payload is encapsulated and not directly visible to a passive observer. The opnum pattern, however, is still inferable from the timing and sizes of the encrypted messages.



## What it looks like in logs

SAMR enumeration produces enough log entries to be noticed if the target is audited aggressively, and almost none if it is not. What shows up depends heavily on audit policy and on whether the target is a domain controller.

### Common events on any target

| Log | Event ID | Trigger |
|:---|:---||
| Security | 4624 | The inbound SMB session logon. Logon Type 3 (network). Enabled by default. |
| Security | 4634 | The logon session ending at the end of the enumeration. |
| Security | 4672 | Fires if the authenticating account is a privileged account. |
| Security | 5140 | Tree connect to `IPC$`. Requires "Audit File Share" enabled. |
| Security | 5145 | Access to the `samr` named pipe. Requires "Audit Detailed File Share" enabled. |

### Events specific to domain controllers

Domain controllers have richer visibility into SAMR enumeration than member servers because SAMR calls on a DC touch the directory. The Directory Service access category, if enabled, fires:

| Log | Event ID | Trigger |
|:---|:---||
| Security | 4662 | Directory Service object access. Fires when Active Directory internals are read. Each `SamrQueryInformationUser2` call can produce one or more of these, depending on which attributes are read. Very noisy but very high fidelity when tuned. |
| Security | 4798 | A user's local group membership was enumerated. Fires for `SamrGetGroupsForUser` style calls if the tool ever goes there. |
| Security | 4799 | A security enabled local group membership was enumerated. |

The volume of 4662 events during a `samrdump.py` run against a domain controller is striking. A small test lab with a handful of users will produce dozens of 4662 entries. A production domain will produce thousands. This is a feature, not a bug: it is exactly the signal a detection engineer needs to spot mass enumeration.

### Sysmon content

Sysmon Event ID 3 (Network connection) captures the inbound port 445 connection. Sysmon Event ID 18 (Pipe connected) captures the open on `\pipe\samr` if the Sysmon config watches it. Olaf Hartong and Florian Roth's public Sysmon configurations both include rules that cover the SAMR pipe.



## Detection and defense

### Detection opportunities

The signature traffic of a `samrdump.py` run against a domain controller is a sustained burst of `SamrOpenUser` and `SamrQueryInformationUser2` opnums, one pair per account, running at a rate far faster than any human administrator would issue them. Detection opportunities cluster around that pattern.

**Volume based detections on 4662.** A count of 4662 events per source account per time window, with a threshold tuned to the environment, catches mass enumeration cleanly. Legitimate replication and administrative activity is bursty but usually lower volume. A hundred plus 4662 events in a minute from a non administrative workstation is a strong signal.

**Named pipe access from unexpected sources.** Event 5145 with `RelativeTargetName` containing `samr` from a workstation that has never before touched SAMR is worth alerting on. Most endpoints have no legitimate reason to open `\pipe\samr`.

**Non administrative accounts querying SAMR.** A help desk or low privilege account reading every user record in the domain is suspicious. Correlating 5145 events on `samr` with the source account's job function is a high quality signal in environments where role information is available.

A starter Sigma rule for the pipe access pattern:

```yaml
title: SAMR Named Pipe Access from Unexpected Source
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5145
    RelativeTargetName|contains: '\samr'
  filter_computer_accounts:
    SubjectUserName|endswith: '$'
  condition: selection and not filter_computer_accounts
level: medium
```

Tune by adding an allowlist of administrative accounts and management servers legitimately expected to perform SAMR enumeration.

### Preventive controls

The controls that matter for SAMR enumeration are the ones that restrict who can authenticate, what authenticated users can see, and how the traffic is monitored.

- **Audit `RestrictAnonymous` and `RestrictAnonymousSAM`.** Both should be `1` on every Windows system. Modern defaults are correct, but legacy images and inherited Group Policy sometimes regress these.
- **Block SAMR access from unprivileged user workstations.** "Network access: Restrict clients allowed to make remote calls to SAM" is a local security policy setting introduced in Windows 10 1607 that restricts SAMR to specific groups. Enabling it dramatically reduces the attack surface on workstations and has minimal impact on legitimate tooling, which is almost always administrative.
- **Require SMB signing and encryption.** This does not prevent an authenticated caller from running SAMR enumeration, but it closes relay based avenues for acquiring the credentials that make the enumeration possible. See [`smbclient.py`](../05_smb_tools/smbclient.md) for the broader SMB hardening discussion.
- **Enable directory service auditing on domain controllers.** Specifically, enable "Audit Directory Service Access" and its subcategory "Audit Directory Service Changes" in advanced audit policy. This is what populates Event ID 4662 with useful attribute level detail.
- **Enable detailed file share auditing.** "Audit Detailed File Share" produces the 5145 events needed to attribute named pipe activity. Plan for the volume and filter noisy paths, but keep the coverage on sensitive pipes including `samr`, `lsarpc`, `drsuapi`, `svcctl`, `winreg`, and `atsvc`.
- **Monitor for low privilege accounts performing high volume directory reads.** The earliest signal of a foothold leveraging `samrdump.py` or any equivalent is a workstation account enumerating the directory at an implausible rate. SIEM correlation rules that score directory read volume by the authenticating account's privilege tier catch this class of activity well.



## Related tools and attack chains

`samrdump.py` is often the first authenticated recon step after a domain credential is obtained. The information it returns feeds almost every subsequent tool.

- **[`rpcdump.py`](rpcdump.md).** Confirms SAMR is available on the target. Run this first against new hosts to verify the SAMR UUID is registered.
- **[`lookupsid.py`](lookupsid.md).** The companion enumeration path, using the `[MS-LSAT]` interface instead of SAMR. Where `samrdump.py` walks users by enumerating them from the domain handle, `lookupsid.py` brute forces RIDs against LSAT. The two tools produce overlapping results with different coverage. Use both.
- **[`net.py`](net.md).** An alternative SAMR client built into Impacket. Offers a command line closer to the Windows `net.exe` feel, with subcommands for users, groups, computers, and local groups.
- **[`GetUserSPNs.py`](GetUserSPNs.md).** Once `samrdump.py` reveals service accounts, this tool requests service tickets for them for Kerberoasting. The account names and UAC flags from `samrdump.py` are what drive the target selection.
- **[`GetNPUsers.py`](GetNPUsers.md).** For accounts whose UAC includes `DONT_REQUIRE_PREAUTH` (`0x400000`), this tool performs AS-REP Roasting. Again, the target list comes directly from `samrdump.py` output.
- **[`findDelegation.py`](findDelegation.md).** For accounts whose UAC includes delegation flags, this tool shows the delegation configuration. Same workflow: identify candidates with `samrdump.py`, investigate with `findDelegation.py`.
- **[`secretsdump.py`](../03_credential_access/secretsdump.md).** Where `samrdump.py` reads metadata through the SAMR API, `secretsdump.py` reads the underlying SAM and NTDS.dit databases directly and extracts password hashes. Both tools answer different questions about the same data.

A common post credential workflow:

1. Obtain a valid domain credential through phishing, password spray, LLMNR poisoning, or prior compromise.
2. Run [`rpcdump.py`](rpcdump.md) against a domain controller to confirm SAMR and LSAT are reachable.
3. Run `samrdump.py` against the domain controller to enumerate every account and its UAC flags.
4. Filter the output for roastable accounts (`DONT_REQUIRE_PREAUTH`) and run [`GetNPUsers.py`](GetNPUsers.md).
5. Filter the output for service accounts and run [`GetUserSPNs.py`](GetUserSPNs.md).
6. Crack the offline hashes with hashcat.
7. Use the resulting credentials for lateral movement through [`psexec.py`](../04_remote_execution/psexec.md), [`wmiexec.py`](../04_remote_execution/wmiexec.md), or [`secretsdump.py`](../03_credential_access/secretsdump.md).

Every step after the first reads from the output that `samrdump.py` generated.



## Further reading

- **`[MS-SAMR]`: Security Account Manager (SAM) Remote Protocol.** The authoritative specification. Start at `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/`. Sections 3.1.5.1 through 3.1.5.11 cover the operations used by `samrdump.py`.
- **`impacket/dcerpc/v5/samr.py`.** The Impacket library module that implements the SAMR client. The `h*` helper functions at the bottom of the file are the most readable starting point.
- **Microsoft Advanced Threat Analytics (ATA) documentation on SAMR reconnaissance.** Describes Microsoft's own detection model for SAMR abuse. Relevant even though ATA itself is deprecated, because the detection principles carry to Microsoft Defender for Identity.
- **"Network access: Restrict clients allowed to make remote calls to SAM" policy** at `https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls`. The Microsoft hardening guide for this setting.
- **MITRE ATT&CK T1087.001 (Local Account)** and **T1087.002 (Domain Account)** at `https://attack.mitre.org/techniques/T1087/`.
- **SpecterOps blog, "An ACE Up the Sleeve."** Covers related AD enumeration techniques and the detection engineering around them.
- **BloodHound documentation on SharpHound SAMR collection.** SharpHound's SAMR collection method is functionally equivalent to `samrdump.py` and reading its documentation provides an alternative view of the same protocol.

Run `samrdump.py` against a lab domain controller, then look up every account in the output whose UAC is not the plain `0x200` or `0x210` normal account value. Every oddity in that list is a finding. This exercise turns this article's theory into a repeatable muscle memory for reading account output quickly.
