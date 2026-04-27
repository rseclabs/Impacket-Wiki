
title: "lookupsid.py"
script: "examples/lookupsid.py"
category: "Recon and Enumeration"
status: "Published"
protocols:
  - MSRPC
  - SMB
  - MS-LSAT
  - MS-LSAD
ms_specs:
  - MS-LSAT
  - MS-LSAD
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
  - protocol/lsat
  - protocol/lsad
  - protocol/smb
  - authentication/ntlm
  - authentication/kerberos
  - authentication/null_session
  - technique/enumeration
  - technique/account_discovery
  - technique/sid_walking
  - mitre/T1087/001
  - mitre/T1087/002
  - mitre/T1069/001
  - mitre/T1069/002
  - mitre/T1033
aliases:
  - lookupsid
  - impacket-lookupsid
  - sid_walking
  - ridcycling


# lookupsid.py

> **One line summary:** Brute forces RIDs against a target's Local Security Authority Translation interface, turning every successful RID into a username, group name, or computer account name, returning a complete list of principals without relying on SAMR enumeration.

| Field | Value |
|:---|:---|
| Script | `examples/lookupsid.py` |
| Category | Recon and Enumeration |
| Status | Published |
| Primary protocols | MSRPC, SMB, MS-LSAT, MS-LSAD |
| Primary Microsoft specifications | `[MS-LSAT]`, `[MS-LSAD]`, `[MS-RPCE]` |
| MITRE ATT&CK techniques | T1087.001 Local Account Discovery, T1087.002 Domain Account Discovery, T1069.001 Local Groups, T1069.002 Domain Groups, T1033 System Owner/User Discovery |
| Authentication types supported | Password, NT hash, AES key, Kerberos ccache, NULL session (legacy targets) |
| First appearance in Impacket | Very early (one of the original example tools) |
| Original authors | Javier Kohen, Alberto Solino (`@agsolino`) |



## Prerequisites

This article builds on:

- [`00_Introduction_and_Architecture.md`](Introduction_and_Architecture.md) for the Impacket stack overview.
- [`smbclient.py`](../05_smb_tools/smbclient.md) for the SMB session lifecycle and the four authentication modes.
- [`rpcdump.py`](rpcdump.md) for DCE/RPC, interface UUIDs, string bindings, and the endpoint mapper.
- [`samrdump.py`](samrdump.md) for SIDs, RIDs, the well known RID table, the SAM account object model, and the `h*` helper function convention.

In particular, the SID and RID material from [`samrdump.py`](samrdump.md) is not repeated here. If SIDs, RIDs, the difference between the two, and the well known RID values (500, 501, 502, 512, 513, 519, and so on) do not already feel familiar, spend five minutes with that article before continuing.



## What it does

`lookupsid.py` walks the RID space of a Windows target and asks the target to translate each RID into a human readable principal. The tool starts at RID 500 (the built in Administrator) and iterates upward, one RID at a time, until it reaches a configurable ceiling (default 4000). For every RID that corresponds to a real principal, the tool prints the domain name, the principal name, and the principal type: user, group, alias, computer account, or well known identifier.

The technique is called **SID walking** or **RID cycling**. It has been in the security research toolkit since the late 1990s, when Windows NT's default configuration exposed this translation interface anonymously. The name "lookupsid" comes from the underlying RPC operation, `LsarLookupSids`, which is the protocol call that does the actual translation.

Where [`samrdump.py`](samrdump.md) reads the user list by enumerating the database through the Security Account Manager interface, `lookupsid.py` reads it by translating one identifier at a time through the Local Security Authority Translation interface. The two tools answer overlapping but different questions, and they are subject to different access controls. Many environments that restrict SAMR enumeration still permit LSAT translation, which is exactly why `lookupsid.py` remains useful in 2026.

Running the tool against a domain controller returns a list of every domain principal whose RID falls below the ceiling. Running it against a workstation or member server returns the local principals. In both cases the output is a flat list with name, type, and RID, suitable for piping into follow up tools or into a CSV.



## Why it exists

The Local Security Authority is the Windows subsystem that tracks user identity, policy, and security privileges on every Windows host. It was part of Windows NT from the beginning. The subsystem has an RPC interface for remote queries, which is how tools like User Manager, Group Policy editors, and the MMC snap ins interact with remote machines. That RPC interface is `\pipe\lsarpc`.

`lookupsid.py` targets a specific operation in that interface: SID to name translation. The operation exists because Windows needs a way to render SIDs as friendly names. When File Explorer shows an ACL on a file, the underlying data is a list of SIDs. The strings you see, like `DOMAIN\alice` and `BUILTIN\Administrators`, come from `LsarLookupSids` calls against either the local LSA or a remote LSA.

The same operation, from a security researcher's perspective, is the fastest way to enumerate a Windows principal list without reading the database directly. You construct a candidate SID by combining the known domain SID with a guessed RID, call `LsarLookupSids`, and if the RID is valid the server returns the name. Repeat for every RID in a reasonable range. This approach works because:

- **RIDs are dense.** Microsoft assigns them sequentially. A default domain has RIDs in the 500 to 502 range for built in accounts and then a gap to 1000 or 1104 where user creation begins. From there, every new principal gets the next available RID. Iterating through the range hits something most of the time.
- **Translation is a lightweight operation.** The target does not have to enumerate a list. It just has to answer a single question: does this SID correspond to a named principal? That makes the access control question different from the enumeration question. A target that says "no" to `SamrEnumerateUsersInDomain` may happily answer `LsarLookupSids` on individual SIDs, because the latter looks like a normal display rendering call.
- **The interface is widely reachable.** `\pipe\lsarpc` is open on virtually every Windows host that accepts SMB connections at all. Restricting it breaks a lot of legitimate tooling, so defenders rarely lock it down completely.

`lookupsid.py` exists because the Impacket authors needed a portable, scriptable version of this historical reconnaissance technique that works from Linux and integrates cleanly with the rest of the Impacket ecosystem.



## The protocol theory

As in the [`samrdump.py`](samrdump.md) article, the SMB and MSRPC foundations are not re explained here. What follows is specific to LSAT and to the brute force translation approach.

### The LSA subsystem

On a Windows host the Local Security Authority is a service (`LSASS.exe`) that owns authentication, local policy, privilege tokens, and SID translation. Remote access to that service is exposed through the `\pipe\lsarpc` named pipe. The interface UUID is `12345778-1234-abcd-ef00-0123456789ab`, version 0.0. You will recognize that UUID from the [reference table in `rpcdump.py`](rpcdump.md#interfaces-and-uuids) where it was labeled LSARPC.

### Two specifications, one interface

The RPC interface behind `\pipe\lsarpc` is documented across two Microsoft specifications that share the same wire protocol:

- **`[MS-LSAD]`: Local Security Authority (Domain Policy) Remote Protocol.** Operations for reading and writing local security policy: rights assignments, trusted domain objects, LSA secrets, private data. This is the spec that covers `LsarOpenPolicy2` and `LsarQueryInformationPolicy2`.
- **`[MS-LSAT]`: Local Security Authority (Translation Methods) Remote Protocol.** Operations for translating SIDs to names and names to SIDs. This is the spec that covers `LsarLookupSids` and `LsarLookupNames`.

The two specs define different operations but they ride on the same RPC interface and the same named pipe. Impacket mirrors this split in its library: `impacket/dcerpc/v5/lsad.py` and `impacket/dcerpc/v5/lsat.py` are two modules that both operate on the same bound connection. `lookupsid.py` imports from both.

### The policy handle pattern

Every call into LSARPC needs a **policy handle**. You cannot just call `LsarLookupSids` cold. The flow is:

1. Open the RPC connection and bind to the LSARPC UUID.
2. Call `LsarOpenPolicy2` to request a policy handle with specific access rights.
3. Use that policy handle in every subsequent call.
4. Call `LsarClose` at the end to release the handle.

The pattern is almost identical to the handle based model described in [`samrdump.py`](samrdump.md#the-handle-based-object-model), with one difference: LSAT has only one layer of handles (the policy handle itself), whereas SAMR has three layers (server, domain, user). LSAT is simpler because translation is a stateless operation from the perspective of the protocol.

### Discovering the domain SID

Before `lookupsid.py` can build candidate SIDs, it needs the domain SID. It obtains it from the target itself using an LSAD operation:

- `LsarQueryInformationPolicy2` with the `PolicyPrimaryDomainInformation` class returns the primary domain SID if the target is domain joined.
- `LsarQueryInformationPolicy2` with the `PolicyAccountDomainInformation` class returns the SID of the local account database (the SAM on a workstation, the built in domain on a DC).

Against a domain controller the tool asks for the primary domain information, because the interesting SIDs are the AD domain SIDs. Against a workstation it falls back to the account domain information, because there is no primary domain in the traditional sense. The Impacket source handles both paths.

Once the domain SID is known, `lookupsid.py` can construct any candidate SID by concatenating the domain SID with a RID:

```text
Domain SID:  S-1-5-21-1170647656-860703057-891382899
Candidate:   S-1-5-21-1170647656-860703057-891382899-500
Result:      TEST\Administrator (User)
```

### `LsarLookupSids` and the lookup levels

The translation call is `LsarLookupSids`. The Impacket helper `hLsarLookupSids` wraps it. The call takes three things:

1. A policy handle.
2. An array of SIDs to translate.
3. A **lookup level** that tells the LSA how to resolve SIDs it does not know locally.

Lookup levels matter because a single LSA might be asked to translate SIDs from foreign domains. The levels control what the LSA will do when it cannot answer locally.

| Level | Behavior |
|:---|:---|
| `LsapLookupWksta` | Workstation mode. Answer from local cache, forward nothing. Fastest, lowest visibility. |
| `LsapLookupPDC` | Primary Domain Controller mode. Forward unknown SIDs to the PDC. Useful for walking trusted domains. |
| `LsapLookupTDL` | Trusted Domain List mode. Use the trusted domain list to forward. |
| `LsapLookupGC` | Global Catalog mode. Forward to a Global Catalog server. Covers forest wide resolution. |

`lookupsid.py` uses `LsapLookupWksta` by default. That is the quietest option, and it is almost always sufficient because the tool is asking the target to resolve SIDs from the target's own domain. The `-domain-sids` flag changes this behavior to enumerate trust relationships, at which point more ambitious lookup levels come into play.

### The SID_NAME_USE enum

Every successful `LsarLookupSids` response carries a type for each resolved name. The enum is documented in `[MS-LSAT]` section 2.2.14.

| Value | Name | Meaning |
|:---|:---||
| 1 | `SidTypeUser` | A user account |
| 2 | `SidTypeGroup` | A domain group (global or universal) |
| 3 | `SidTypeDomain` | A domain itself |
| 4 | `SidTypeAlias` | A local group (alias) |
| 5 | `SidTypeWellKnownGroup` | A well known group such as `Everyone`, `Authenticated Users`, `System` |
| 6 | `SidTypeDeletedAccount` | An account that once existed but has been deleted |
| 7 | `SidTypeInvalid` | Not a valid SID |
| 8 | `SidTypeUnknown` | Valid SID but the LSA does not know who it is |
| 9 | `SidTypeComputer` | A computer (machine) account |
| 10 | `SidTypeLabel` | A mandatory label (for Mandatory Integrity Control) |

`lookupsid.py` prints this type next to every result, which is what distinguishes it from `samrdump.py`. Where `samrdump.py` walks the user list, `lookupsid.py` discovers **everything**: users, groups, aliases, computers, and well known principals. That breadth is often the reason researchers reach for it first.

### Why brute forcing works

RIDs in a Windows domain are assigned sequentially. Microsoft's RID allocator hands out the next available number from a pool as each new principal is created. The numbering scheme follows a predictable pattern:

- Built in principals use RIDs 500 through a small number in the low 500s.
- Creation begins at either 1000 or 1104, depending on Windows version.
- Each new principal increments the counter.

A domain that has ever created 3000 principals (across users, groups, and computers) has RIDs packed into roughly the range 500 to 4104. Iterating through 500 to 4000 therefore hits most things. Gaps appear where principals have been deleted, because RIDs are never reused, but the hit rate is still high. This is why the default `maxRid` of 4000 is a sensible starting point for most domains. For very large environments the ceiling needs to be raised.

The tool is rate limited only by network round trips and batch size. Impacket sends batches of SIDs in a single `LsarLookupSids` call, so a full walk of 3500 RIDs completes in seconds to minutes depending on the link and the target's responsiveness.



## How the tool works internally

The script's logic is small. Reading it top to bottom is the best way to see the full flow.

1. **Argument parsing.** Positional arguments: `target` (standard Impacket format) and `maxRid` (default 4000). Optional flags: `-hashes`, `-k`, `-no-pass`, `-aesKey`, `-domain-sids`, `-dc-ip`, `-target-ip`, `-port`, `-debug`, `-ts`.

2. **SMB session establishment.** Standard `SMBConnection` flow. See [`smbclient.py`](../05_smb_tools/smbclient.md).

3. **DCERPC bind to LSARPC.** Open the `\pipe\lsarpc` named pipe inside the SMB session, issue a DCERPC Bind for UUID `12345778-1234-abcd-ef00-0123456789ab`, receive the bind acknowledgment.

4. **`LsarOpenPolicy2`.** Request a policy handle with `MAXIMUM_ALLOWED` access.

5. **Domain SID discovery.** Call `LsarQueryInformationPolicy2` with `PolicyPrimaryDomainInformation` first. If the response carries a usable domain SID, keep it. Otherwise, call again with `PolicyAccountDomainInformation` and use the account domain SID. The tool logs which it ended up using, which is often the first clue about whether the target is domain joined.

6. **RID iteration.** Build an array of candidate SIDs for RIDs 500 through `maxRid`. Batch them into groups of reasonable size (Impacket uses a batch size tuned to avoid exceeding the RPC message limit) and call `hLsarLookupSids` for each batch with `LsapLookupWksta` as the lookup level.

7. **Parse each response.** For each translated SID, extract the domain name (looked up from the `ReferencedDomains` list by index), the principal name, and the `SID_NAME_USE` type. Print one line per result.

8. **Shutdown.** `LsarClose` on the policy handle. DCERPC disconnect. SMB logoff. TCP close.

A small detail worth noticing in the source: the output index (`soFar + n`) tracks how many successful lookups have occurred, not how many RIDs have been tried. A domain with many gaps in its RID range will have an output index lower than its current RID.



## Authentication options

Same four credential types as every other SMB tunneled Impacket tool. See [`smbclient.py`](../05_smb_tools/smbclient.md) for the full pattern. Short form for this tool:

### Cleartext password

```bash
lookupsid.py CORP/alice:'S3cret!'@dc01.corp.local
```

### NT hash

```bash
lookupsid.py -hashes :<nthash> CORP/alice@dc01.corp.local
```

### AES key

```bash
lookupsid.py -aesKey <hex> CORP/alice@dc01.corp.local
```

### Kerberos ccache

```bash
export KRB5CCNAME=/path/to/alice.ccache
lookupsid.py -k -no-pass CORP/alice@dc01.corp.local
```

### NULL session

```bash
lookupsid.py @target.corp.local
```

As with SAMR, NULL session LSAT lookups will fail on a modern Windows target that has `RestrictAnonymous` set to 1 or higher. They sometimes succeed against legacy Samba, older Windows, or misconfigured NAS appliances. Always worth a try when enumerating an unfamiliar environment.

### Access rights

LSAT translation requires less access than SAMR enumeration in many configurations. A domain user who has been explicitly denied SAMR enumeration can still often run `lookupsid.py` successfully, because the access check on `LsarLookupSids` is separate from the access check on `SamrEnumerateUsersInDomain`. This asymmetry is a direct result of Microsoft's dual interface design, where translation is treated as a display operation and enumeration as a management operation.



## Practical usage

### Default invocation against a domain controller

```text
$ lookupsid.py CORP/alice:'S3cret!'@dc01.corp.local
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Brute forcing SIDs at dc01.corp.local
[*] StringBinding ncacn_np:dc01.corp.local[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1170647656-860703057-891382899
498: CORP\Administrator (SidTypeUser)
499: CORP\Guest (SidTypeUser)
500: CORP\krbtgt (SidTypeUser)
501: CORP\Domain Admins (SidTypeGroup)
502: CORP\Domain Users (SidTypeGroup)
503: CORP\Domain Guests (SidTypeGroup)
504: CORP\Domain Computers (SidTypeGroup)
505: CORP\Domain Controllers (SidTypeGroup)
506: CORP\Cert Publishers (SidTypeAlias)
507: CORP\Schema Admins (SidTypeGroup)
508: CORP\Enterprise Admins (SidTypeGroup)
...
590: CORP\DC01$ (SidTypeUser)
591: CORP\svc_sql (SidTypeUser)
592: CORP\svc_backup (SidTypeUser)
593: CORP\alice (SidTypeUser)
594: CORP\bob (SidTypeUser)
595: CORP\charlie (SidTypeUser)
596: CORP\svc_roastme (SidTypeUser)
597: CORP\FS01$ (SidTypeUser)
...
```

The RID in the output is implicit. The first column is the running count of successful lookups, which is useful for rough sizing but is not the RID itself. To derive the RID, remember that iteration starts at 500 and increments from there, skipping nothing in the request side, only in the display side.

Two quick observations from a real output of this kind:

- **Computer accounts appear as `SidTypeUser` with a trailing `$`**, because Active Directory models computer accounts as specialized user accounts. `DC01$` and `FS01$` are computers. In Impacket's display, they are flagged as `SidTypeUser`, but a trailing `$` is the distinguishing mark.
- **Built in groups appear as `SidTypeAlias`** when they come from the `Builtin` domain (for example, `BUILTIN\Administrators` with RID 544). They appear as `SidTypeGroup` when they are domain groups (for example, `Domain Admins` with RID 512).

### Increasing the RID ceiling

For a large environment, bump the ceiling:

```bash
lookupsid.py CORP/alice:'S3cret!'@dc01.corp.local 10000
```

The `10000` positional argument replaces the default `maxRid` of 4000. Expect the run to take proportionally longer.

### Against a workstation

```bash
lookupsid.py CORP/alice:'S3cret!'@ws01.corp.local
```

Same output format, but the `Domain SID` will be the machine account domain SID (the one that identifies the local SAM on that workstation). You will see local accounts like `Administrator` (RID 500), `Guest` (RID 501), and any local users created on that box.

### Enumerating trust relationships

```bash
lookupsid.py -domain-sids CORP/alice:'S3cret!'@dc01.corp.local
```

The `-domain-sids` flag changes the behavior. Instead of walking RIDs in the primary domain SID, the tool enumerates known domain SIDs, which can reveal trusted domains and forests. This mode forwards unknown SIDs to the DC, so the target sees more outbound RPC traffic, which has some detection implications.

### Comparing with samrdump output

A useful exercise is running `lookupsid.py` and [`samrdump.py`](samrdump.md) side by side against the same target and diffing the outputs. The `samrdump.py` output includes rich metadata (UAC flags, timestamps) but only user accounts. The `lookupsid.py` output is leaner per entry but covers users, groups, aliases, and computers. Together they give a more complete picture than either alone.

### Key flags

| Flag | Meaning |
|:---|:---|
| `maxRid` (positional) | Upper bound of the brute force range. Default 4000. |
| `-hashes LMHASH:NTHASH` | NT hash authentication. |
| `-aesKey <hex>` | Kerberos AES key. |
| `-k` | Use a Kerberos ticket from ccache. |
| `-no-pass` | Skip the password prompt. |
| `-domain-sids` | Enumerate trust related SIDs in addition to the primary domain. |
| `-dc-ip <ip>` | Explicit DC IP for Kerberos. |
| `-target-ip <ip>` | Explicit target IP when DNS lookup fails. |
| `-port <135\|139\|445>` | Alternative transport port. Default 445. |
| `-debug` | Full protocol trace. |
| `-ts` | Timestamp every log line. |



## What it looks like on the wire

For the SMB session setup and the DCERPC bind, see the wire walkthroughs in [`smbclient.py`](../05_smb_tools/smbclient.md) and [`rpcdump.py`](rpcdump.md) respectively. The LSAT specific traffic, visible in Wireshark with the `lsarpc` display filter, looks like this.

1. **LSARPC `LsarOpenPolicy2` Request / Response.** Establishes the policy handle.
2. **LSAD `LsarQueryInformationPolicy2` Request / Response.** Retrieves the domain SID.
3. **Loop of LSAT `LsarLookupSids` Request / Response pairs.** Each request carries a batch of candidate SIDs. Each response carries the translated names and the `SID_NAME_USE` types.
4. **LSARPC `LsarClose` Request / Response.** Releases the policy handle.

The signature pattern of `lookupsid.py` on the wire is the long burst of `LsarLookupSids` calls. A legitimate workstation rendering a file ACL might make one or two such calls. `lookupsid.py` makes many in rapid succession. An observer with Wireshark or a network IDS can count them and see the burst immediately.

If SMB signing or SMB encryption is negotiated during session setup (the default against modern Windows), the RPC payload is protected. The frequency and size pattern of the traffic, however, still reveals the bulk translation activity.



## What it looks like in logs

Many of the events overlap with [`samrdump.py`](samrdump.md). The differences are in which named pipe is touched and which directory service events fire.

### Common events on any target

| Log | Event ID | Trigger |
|:---|:---||
| Security | 4624 | Inbound SMB session logon, Logon Type 3. |
| Security | 4634 | Logon session end. |
| Security | 4672 | Fires for administrative authentications. |
| Security | 5140 | Tree connect to `IPC$`. Requires "Audit File Share" enabled. |
| Security | 5145 | Named pipe access. The relative target path will contain `lsarpc`, not `samr`. |

### Events specific to domain controllers

| Log | Event ID | Trigger |
|:---|:---||
| Security | 4662 | Directory Service object access. Fires when `LsarLookupSids` triggers AD reads on a DC. High volume during a `lookupsid.py` run. Requires "Audit Directory Service Access" enabled. |

The volume of 4662 events during `lookupsid.py` against a DC is higher than during `samrdump.py`, because each translated SID causes its own read. A detection engineer looking for mass enumeration can tune a threshold on 4662 events per source account per time window and catch both tools with the same rule.

### Contrast with samrdump

If you monitored both tools running in sequence and filtered by named pipe, the footprint would differ:

- `samrdump.py` leaves 5145 events for `\pipe\samr`.
- `lookupsid.py` leaves 5145 events for `\pipe\lsarpc`.

Both leave 4624 and 4662 events that look similar. The pipe name is the clearest signal distinguishing the two tools in log review.



## Detection and defense

### Detection opportunities

The signature traffic of a `lookupsid.py` run is unusually bursty translation activity. Detections that target this pattern catch the tool cleanly.

**Volume based detections on 5145 for `\pipe\lsarpc`.** A single source generating many events in a short time window is anomalous. Legitimate LSAT use is sparse, almost always a handful of calls during interactive ACL browsing. Mass translation is an attacker signal.

**4662 bursts on domain controllers.** Same pattern as for SAMR enumeration. A surge of Directory Service access events from a single workstation is a strong indicator. A SIEM correlation rule that scores the burst against the workstation's normal behavior baseline will catch `lookupsid.py`, `samrdump.py`, and the BloodHound collectors in one sweep.

**Non administrative accounts performing bulk translation.** Ordinary user accounts rarely need to translate many SIDs in a short window. Correlate the source account's role against the pipe accessed and the call volume. Help desk and admin roles have legitimate use cases. Regular users do not.

**Named pipe access from unusual hosts.** An internet facing web server or a building automation controller suddenly connecting to `\pipe\lsarpc` on a domain controller is not normal. Allowlist expected sources and alert on others.

A starter Sigma style rule for the pipe access pattern:

```yaml
title: LSARPC Named Pipe Access from Unexpected Source
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5145
    RelativeTargetName|contains: '\lsarpc'
  filter_computer_accounts:
    SubjectUserName|endswith: '$'
  condition: selection and not filter_computer_accounts
level: medium
```

Tune by allowlisting administrative systems, domain joined management servers, and accounts whose job function involves mass SID resolution.

### Preventive controls

LSAT is harder to restrict than SAMR because it is more integrated into ordinary Windows display logic. Still, several controls reduce the exposure materially.

- **`RestrictAnonymous` and `RestrictAnonymousSAM`.** Set to `1` on every Windows system. This closes the NULL session path to LSAT and SAMR alike.
- **`TurnOffAnonymousBlock` must stay at `0` or unset.** In some hardened environments this registry value has been flipped experimentally and then left enabled, which re opens NULL session paths. Audit for this.
- **Be aware that "Network access: Restrict clients allowed to make remote calls to SAM" does NOT cover LSAT.** The SAM call restriction applies to `\pipe\samr`. LSAT traffic on `\pipe\lsarpc` is a separate surface. Defenders who rely solely on the SAM restriction should expect LSAT enumeration to still succeed. This is a common blind spot.
- **Audit detailed file share.** Turn on the policy so that 5145 events fire for named pipe access. Filter noisy paths as needed, but retain coverage for `lsarpc`, `samr`, `drsuapi`, `svcctl`, `winreg`, and `atsvc`.
- **Monitor directory service access auditing.** On domain controllers, the "Audit Directory Service Access" policy produces 4662 events that capture the per attribute reads triggered by LSAT translation. This is the most fidelity rich signal available short of network DPI.
- **Segment LSAT reachability.** A workstation in a standard user VLAN does not need to reach `\pipe\lsarpc` on the domain controller. Tier based access control, enforced at the network and host firewall layers, cuts the reachable attack surface significantly.
- **Monitor for LSAT activity from non Windows source operating systems.** A significant fraction of `lookupsid.py` use happens from Linux attacker hosts. Any EDR or NDR telemetry that can identify the source operating system is a useful additional signal.



## Related tools and attack chains

`lookupsid.py` fits neatly beside [`samrdump.py`](samrdump.md) in the early reconnaissance phase. The two tools are complementary, not redundant.

- **[`rpcdump.py`](rpcdump.md).** Before targeting LSAT, confirm the LSARPC UUID is registered on the target. This is especially important against non Windows SMB servers, which may or may not expose LSAT.
- **[`samrdump.py`](samrdump.md).** Run alongside `lookupsid.py`. SAMR gives you rich per user metadata. LSAT gives you broader principal coverage (users, groups, aliases, computers). Use both.
- **[`net.py`](net.md).** Exposes additional enumeration paths over SAMR with a command line that mirrors Windows `net.exe`. Good for cross checking findings.
- **[`GetUserSPNs.py`](GetUserSPNs.md) and [`GetNPUsers.py`](GetNPUsers.md).** The account lists produced by `lookupsid.py` feed directly into these Kerberos attack tools. A `svc_roastme` account that shows up in both SAMR and LSAT output is a candidate for Kerberoasting and AS-REP Roasting.
- **[`findDelegation.py`](findDelegation.md).** Computer accounts (the trailing `$` entries in `lookupsid.py` output) that show up with unusual SIDs are worth checking for delegation configuration.
- **BloodHound and SharpHound.** BloodHound's collector uses LSAT alongside LDAP and SAMR. The data shapes produced by `lookupsid.py` are a subset of what BloodHound ingests. For deep, relationship aware reconnaissance, BloodHound is the target. `lookupsid.py` is faster when all you need is a name list.

A common reconnaissance sequence that uses this tool:

1. Obtain a valid domain credential.
2. Confirm interface availability with [`rpcdump.py`](rpcdump.md).
3. Run `lookupsid.py` against a domain controller for a complete principal list, including computer accounts and groups.
4. Run [`samrdump.py`](samrdump.md) against the same DC for user metadata and UAC flags.
5. Combine the two outputs and filter for high value findings: `DONT_REQUIRE_PREAUTH` accounts, `TRUSTED_FOR_DELEGATION` accounts, service accounts with interesting names.
6. Feed the resulting target list into [`GetUserSPNs.py`](GetUserSPNs.md), [`GetNPUsers.py`](GetNPUsers.md), or [`findDelegation.py`](findDelegation.md).

The overlap is deliberate. In the wild, environments that block one enumeration path often leave the other open. Redundant reconnaissance paths buy the researcher resilience.



## Further reading

- **`[MS-LSAT]`: Local Security Authority (Translation Methods) Remote Protocol.** The authoritative specification. `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/`. Section 3.1.4 covers the lookup operations.
- **`[MS-LSAD]`: Local Security Authority (Domain Policy) Remote Protocol.** Companion specification for policy queries. Section 3.1.4.6 covers `LsarQueryInformationPolicy2`, which `lookupsid.py` uses for domain SID discovery.
- **`impacket/dcerpc/v5/lsat.py` and `impacket/dcerpc/v5/lsad.py`.** The Impacket library modules behind this tool. Short and well organized.
- **"SMB Null Session Enumeration" historical papers.** The technique `lookupsid.py` automates was originally described in late 1990s advisories. Search for "Red Button" and "NetBIOS enumeration" for the historical context, which helps explain why every piece of modern hardening guidance mentions `RestrictAnonymous`.
- **MITRE ATT&CK T1087.001 and T1087.002** at `https://attack.mitre.org/techniques/T1087/`.
- **Microsoft "Security considerations for remote access to the Security Account Manager" documentation.** Discusses SAM related controls and explicitly notes that they do not cover LSAT.
- **SpecterOps "Death from Above: Lateral Movement from Azure to On-Prem AD"** and related material on SID enumeration in hybrid environments. Demonstrates how this class of technique scales into cloud hybrid environments.

Run `lookupsid.py` and [`samrdump.py`](samrdump.md) against the same lab domain controller. Diff the output. Note which principal types only one of the two tools surfaces. Repeat with a member server and a workstation. Three runs across three target types will teach you more about the LSA and SAM exposure of a Windows environment than a day of reading.
