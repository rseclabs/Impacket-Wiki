
title: "smbpasswd.py"
script: "examples/smbpasswd.py"
category: "AD Modification"
status: "Published"
protocols:
  - SMB
  - MSRPC
ms_specs:
  - MS-SAMR
mitre_techniques:
  - T1098
  - T1556
auth_types:
  - password
  - ntlm_hash
  - kerberos
tags:
  - impacket
  - impacket/examples
  - category/ad_modification
  - status/published
  - protocol/smb
  - protocol/msrpc
  - ms-spec/ms-samr
  - technique/password_change
  - technique/account_manipulation
  - mitre/T1098
  - mitre/T1556
  - deprecated-in-favor-of-changepasswd
aliases:
  - smbpasswd


# smbpasswd.py

> **One line summary:** Older password change tool with a single purpose, speaking MS-SAMR over SMB exclusively, using the `SamrUnicodeChangePasswordUser2` RPC call to change a user's password over an SMB named pipe connection to the `\samr` endpoint on TCP 445; authored originally by `@snovvcrash` (see the October 2020 blog post "Pretending to be smbpasswd with Impacket"), later extended by `@bransh` and `@Alef-Burzmali` with NTLM hash as new password support (PR #381), expired password change handling (n00py's 2021 research on resetting expired passwords remotely), and Kerberos authentication support for the authenticating principal (p0dalirius, PR #1177); functionally a proper subset of the newer [`changepasswd.py`](changepasswd.md) which consolidates smbpasswd, rpcpasswd, kpasswd, and an LDAP implementation into a single tool via `-protocol` selection; **still ships in current Impacket but is flagged for eventual deprecation** per the PR #1559 discussion, so the documentation here focuses on what smbpasswd specifically does, why it was important historically, and when to pick smbpasswd over changepasswd (short answer: almost never in new work, but occasionally for scripts that integrated it before changepasswd existed and for cases where the minimal surface covering only one protocol is desirable); **completes AD Modification at 7 of 7 articles ✅, making it the 9th complete category for the wiki (69% complete by category)**.

| Field | Value |
|:---|:---|
| Script | `examples/smbpasswd.py` |
| Category | AD Modification |
| Status | Published (tool is deprecated in favor of changepasswd.py) |
| Primary author | `@snovvcrash` (original, October 2020) |
| Contributing authors | `@bransh`, `@Alef-Burzmali` (NTLM hash as new password, expired password handling), `p0dalirius` (Kerberos auth, PR #1177) |
| Primary protocols | SMB (transport), MSRPC SAMR (content) |
| Primary Microsoft specifications | `[MS-SAMR]` Security Account Manager Remote Protocol |
| MITRE ATT&CK techniques | T1098 Account Manipulation, T1556 Modify Authentication Process |
| Authentication types | Password, NTLM hash (`-hashes`), Kerberos (`-k`) |
| Supersession | Superseded by `changepasswd.py` (PR #1559, May 2023) |



## Prerequisites

Prerequisites are a strict subset of changepasswd's. Read:

- [`changepasswd.py`](changepasswd.md) first. It covers the full protocol landscape (SMB SAMR, RPC SAMR, kpasswd, LDAP) and the SAMR theory (RPC calls, password encryption, info levels for SetInformationUser). smbpasswd.py is a subset of that tool's SMB SAMR handler with a narrower CLI.
- [`samrdump.py`](../01_recon_and_enumeration/samrdump.md) for SAMR protocol foundations.
- [`addcomputer.py`](addcomputer.md) and [`rbcd.py`](rbcd.md) for AD Modification category context.

If you've read the changepasswd.py article, most of the technical content below will be familiar. This article exists for completeness of historical tool coverage and for readers researching offensive writeups from before 2023 that reference smbpasswd specifically.



## What it does

`smbpasswd.py` changes a user's password over SMB SAMR. Canonical invocation:

```text
$ smbpasswd.py ACME.LOCAL/alice@dc01.acme.local
Impacket v0.11.0 - Copyright 2023 Fortra
Current SMB password:
New SMB password:
Retype new SMB password:
[*] Password was changed successfully.
```

Everything is via SMB: TCP 445 connection to the DC, SMB session, SMB tree connect to IPC$, named pipe `\samr`, DCE/RPC bind to SAMR interface, `SamrUnicodeChangePasswordUser2` RPC call.

Two supported operations:

### Password change (primary)

The account whose password is changing authenticates with current credentials and provides new password. Both old and new passwords can be either plaintext or NTLM hashes:

```bash
# Normal change
smbpasswd.py ACME.LOCAL/alice@dc01.acme.local

# With current password on command line
smbpasswd.py ACME.LOCAL/alice:OldPass@dc01.acme.local -newpass 'NewPass123!'

# With current NTLM hash
smbpasswd.py ACME.LOCAL/alice@dc01.acme.local \
    -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 \
    -newpass 'KnownPass123!'

# With new password as NTLM hash
smbpasswd.py ACME.LOCAL/alice:OldPass@dc01.acme.local \
    -newhashes :b2bdbe60565b677dfb133866722317fd
```

### Password reset (via SetInformationUser)

When current password is unknown but the caller has reset rights:

```bash
smbpasswd.py ACME.LOCAL/admin:AdminPass@dc01.acme.local \
    -resetuser alice \
    -newpass 'ResetPass!'
```

Note: some older versions of smbpasswd.py only supported change, not reset. Reset was added later via PR #1207 by stephenbradshaw (originally proposed as a separate `smbresetpasswd.py` script, then folded into smbpasswd). Modern smbpasswd.py supports both; the CLI and flag names may vary between Impacket versions.

### Expired password handling

A key feature that originally motivated the tool's existence:

```bash
# Alice's password has expired; normal login fails, but SAMR change works
smbpasswd.py ACME.LOCAL/alice:ExpiredPass@dc01.acme.local \
    -newpass 'FreshPass123!'
```

n00py's 2021 blog "Resetting Expired Passwords Remotely" documented that `SamrUnicodeChangePasswordUser2` accepts changes against expired passwords where normal logon flows would reject them. smbpasswd.py was one of the first tools to cleanly expose this capability.

### Hash as new password consequence

Setting the new password to an NTLM hash (via `-newhashes`) has a side effect called out in the script header: the account's Kerberos keys do not get updated to match (because deriving Kerberos keys from an NT hash requires the plaintext). After a change that sets only the hash, AES256 and AES128 Kerberos authentication for that account may fail; only RC4 Kerberos (which uses NT hash directly) will work reliably. Setting a plaintext password via `-newpass` rotates all keys consistently.



## Why it exists

### The historical gap

Before smbpasswd.py existed in Impacket, Linux attackers who needed to change a Windows domain user's password over the network had limited options:

- **Samba's `smbpasswd`**: the canonical Linux tool, but focused on Samba server password operations and awkward for AD remote change scenarios.
- **Tools native to Windows**: require a Windows host.
- **Custom scripting**: roll your own SAMR implementation.

snovvcrash's 2020 writeup identified the gap and presented a clean Impacket-based implementation. The name deliberately evokes Samba's tool to signal "this is the remote SMB password change utility for AD, implemented with Impacket's SAMR bindings."

### Key capabilities added over time

- **Initial implementation** (snovvcrash, 2020): basic SAMR change with current password.
- **NTLM hash as new password** (bransh, Alef-Burzmali, PR #381): set new password to a specific hash value without knowing the plaintext.
- **Kerberos authentication** (p0dalirius, PR #1177): authenticate the principal via Kerberos TGT instead of NTLM, useful in environments where NTLM is disabled.
- **Reset mode** (stephenbradshaw, PR #1207, originally standalone smbresetpasswd.py): admin reset of another user's password via SetInformationUser.

### Why it was superseded by changepasswd.py

Alef-Burzmali merged smbpasswd into changepasswd via PR #1559 in May 2023. The consolidation was motivated by:

- **Proliferation of scripts each covering a single protocol**: smbpasswd (SMB SAMR), rpcpasswd (RPC SAMR), kpasswd (Kerberos). Three nearly identical interfaces for related protocols. Hard to maintain consistently.
- **LDAP was missing**: no single Impacket script did LDAP password modification, despite it being the fourth legitimate protocol for password operations.
- **Interface inconsistency**: each script had slightly different CLI flags, different behavior around hashes, different error handling. Users had to relearn each tool.

changepasswd.py presents a single interface with `-protocol` selecting which of the four implementations runs, and `-reset` selecting change vs reset. The four implementations share common logic where possible. This is strictly better than four separate scripts for most users and use cases.

smbpasswd.py ships in current Impacket versions for backward compatibility, but PR #1559 discussion flagged it for eventual removal. Users updating scripts that invoke smbpasswd should migrate to changepasswd.

### When to still pick smbpasswd.py

Short answer: rarely. Specific cases:

- **Existing scripts**: if you have tooling that already calls smbpasswd.py with specific flags, changing to changepasswd.py requires updating the flag set. If the existing integration works, churn is unnecessary.
- **Minimal surface area**: smbpasswd does exactly one thing (SMB SAMR password change), which can be a virtue in constrained scripting scenarios where the extra protocol options of changepasswd add nothing.
- **Documentation search**: older writeups, courseware, and CTF materials reference smbpasswd.py by name. If you're following one of those, using the tool it references matches the walkthrough.

For new work, default to changepasswd.py.



## SAMR theory (cross reference)

The SAMR call flow, password encryption, info levels, and transport mechanics are covered in the [`changepasswd.py`](changepasswd.md) article's "Four protocol theory" section, specifically the "MS-SAMR" subsection. smbpasswd.py uses the same mechanics; cross-reading that section is recommended rather than duplicating here.

Summary of what smbpasswd specifically does:

1. Establish SMB session to DC on TCP 445.
2. Tree connect to IPC$, open named pipe `\samr`.
3. DCE/RPC bind to SAMR interface (UUID `12345778-1234-ABCD-EF00-0123456789AC`).
4. For change: call `SamrUnicodeChangePasswordUser2` with username, old password (or hash), and new password (or hash).
5. For reset (where supported): call `SamrConnect5` → `SamrOpenDomain` → `SamrLookupNamesInDomain` → `SamrOpenUser` → `SamrSetInformationUser` with info level 23/24/25.

The password material is encrypted in transit using ciphers derived from the session key that the underlying impacket.samr module handles automatically.



## How the tool works internally

### Imports

```python
from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.dcerpc.v5 import transport, samr
```

Four imports. Much smaller surface than changepasswd.py, which pulls in Kerberos and LDAP modules as well.

### Class structure

```python
class SMBPasswd:
    def __init__(self, address, domain='', username='',
                 oldPassword='', newPassword='',
                 oldPwdHashLM='', oldPwdHashNT='',
                 newPwdHashLM='', newPwdHashNT=''):
        # ... stash parameters
    
    def connect(self, anonymous=False):
        rpctransport = transport.SMBTransport(self.hostname, filename=r'\samr')
        if anonymous:
            rpctransport.set_credentials(username='', password='', domain='',
                                         lmhash='', nthash='', aesKey='')
        else:
            rpctransport.set_credentials(self.username, self.oldPassword, self.domain,
                                         self.oldPwdHashLM, self.oldPwdHashNT, aesKey='')
        self.dce = rpctransport.get_dce_rpc()
        self.dce.connect()
        self.dce.bind(samr.MSRPC_UUID_SAMR)
    
    def hSamrUnicodeChangePasswordUser2(self):
        resp = samr.hSamrUnicodeChangePasswordUser2(
            self.dce, '\x00', self.username,
            self.oldPassword, self.newPassword,
            self.oldPwdHashLM, self.oldPwdHashNT
        )
        if resp['ErrorCode'] == 0:
            logging.info('Password was changed successfully.')
        else:
            # Parse specific error codes
            if 'STATUS_PASSWORD_RESTRICTION' in str(resp):
                logging.critical('Some password update rule has been violated. For example, the password may not meet length criteria.')
```

The class wraps one SAMR call with appropriate error handling.

### Error codes handled

- `STATUS_PASSWORD_RESTRICTION`: policy violation (length, complexity, history, minimum age).
- `STATUS_ACCOUNT_RESTRICTION`: account-level restrictions (disabled, locked).
- `STATUS_WRONG_PASSWORD`: old password / hash didn't match.
- `STATUS_LOGON_FAILURE`: authentication failure.

The error parsing maps NTSTATUS codes returned by the server to messages a human can read.

### Anonymous bind handling

Interesting subtle feature: the connect method supports an `anonymous=True` path that attempts the SAMR connection without credentials. For password change this is always wrong (the change requires authentication), but the code path exists because SAMR does allow anonymous binds for some operations in older Windows versions. smbpasswd.py authenticates normally by default.

### What the tool does NOT do

- Does NOT support RPC SAMR transport (only SMB). Use changepasswd.py or the original rpcpasswd.py for that.
- Does NOT support Kerberos kpasswd protocol. Use changepasswd.py or kpasswd.py.
- Does NOT support LDAP unicodePwd writes. Use changepasswd.py.
- Does NOT bypass password policy, ACL restrictions, or other checks performed server side.
- Does NOT support bulk operations; one user at a time.



## Authentication options

Standard Impacket authentication for the principal performing the change:

| Option | Notes |
|:---|:---|
| Password (standard) | `user:password@host`. The user IS the target for change mode; for reset mode, the user is the admin. |
| NTLM hash | `-hashes LMHASH:NTHASH`. Often `aad3b435b51404eeaad3b435b51404ee:<nthash>` when only NT hash is available. |
| Kerberos | `-k` with `-no-pass` and `KRB5CCNAME` set. Added by p0dalirius in PR #1177. |

Output password formats:
- Plaintext via `-newpass`
- NTLM hash via `-newhashes`



## Practical usage

### Scenario 1: change your own password

```bash
smbpasswd.py ACME.LOCAL/alice@dc01.acme.local
# Prompts for current and new password
```

The canonical use case.

### Scenario 2: change via captured hash

```bash
smbpasswd.py ACME.LOCAL/alice@dc01.acme.local \
    -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 \
    -newpass 'KnownPass!'
```

Hash captured via secretsdump / Responder / dcsync; used here to rotate the password to something the operator knows.

### Scenario 3: Kerberos authentication

```bash
export KRB5CCNAME=/tmp/alice.ccache
smbpasswd.py -k -no-pass ACME.LOCAL/alice@dc01.acme.local \
    -newpass 'KerbChangedPass!'
```

Works when NTLM is disabled or when existing Kerberos TGT should be reused.

### Scenario 4: expired password recovery

```bash
smbpasswd.py ACME.LOCAL/alice:ExpiredPass@dc01.acme.local \
    -newpass 'NewValidPass123!'
```

Where normal Windows logon fails because the password is expired, SAMR change succeeds. Classic n00py-documented capability.

### Scenario 5: admin resets another user (where supported)

```bash
smbpasswd.py ACME.LOCAL/admin:AdminPass@dc01.acme.local \
    -resetuser alice \
    -newpass 'AdminSetPass!'
```

Uses SetInformationUser. Requires admin privileges on the target user object.

### Key flags (summary)

| Flag | Meaning |
|:---|:---|
| `target` (positional) | `[[domain/]username[:password]@]target`. Target is the DC or server reachable via SMB. |
| `-newpass <pass>` | New plaintext password. |
| `-newhashes LM:NT` | New password as NTLM hash pair. |
| `-hashes LM:NT` | Current password as NTLM hash (for change mode). |
| `-resetuser <user>` | Reset mode target user (where smbpasswd version supports reset). |
| `-k` | Kerberos authentication. |
| `-no-pass` | Don't prompt for password. |
| `-debug` | Verbose debug output. |

Note: exact flag names vary slightly across Impacket versions. The underlying operation is always SAMR over SMB.



## Wire and log signatures

Identical to changepasswd.py's `smb-samr` protocol mode. Cross reference:

- **Wire**: TCP 445 SMB, `\samr` named pipe, DCE/RPC bind to SAMR UUID, `SamrUnicodeChangePasswordUser2` (opnum 55) call. Wireshark filters from changepasswd.py article's "What it looks like on the wire" section.
- **Event logs**: 4723 for change, 4724 for reset. Preceded by 4624 Logon Type 3 for the principal's authentication.
- **Detection**: see changepasswd.py's "Detection and defense" section. Every Sigma rule and baseline approach applies identically to smbpasswd.py traffic.

There is no detection that distinguishes smbpasswd.py from changepasswd.py with `-protocol smb-samr` from native Windows `Ctrl-Alt-Del → Change password`. All three produce identical telemetry on the DC side.



## Related tools and attack chains

smbpasswd.py **completes AD Modification at 7 of 7 articles ✅**. This is the **9th complete category** for the wiki, bringing total category completion to 9 of 13 (69%).

### Related Impacket tools

- **Replacement**: [`changepasswd.py`](changepasswd.md) supersedes smbpasswd.py. Use changepasswd for new work.
- **Complementary**: [`samrdump.py`](../01_recon_and_enumeration/samrdump.md), [`secretsdump.py`](../03_credential_access/secretsdump.md), [`addcomputer.py`](addcomputer.md), [`rbcd.py`](rbcd.md), [`dacledit.py`](dacledit.md), [`owneredit.py`](owneredit.md), [`badsuccessor.py`](badsuccessor.md).

### External alternatives

The same alternatives apply as with changepasswd.py:

- Samba `smbpasswd` (local SMB password change, different operational context).
- Native Windows `net user`, `Ctrl-Alt-Del → Change password`.
- PowerShell `Set-ADAccountPassword`.
- Rubeus `changepw` for Windows-side Kerberos.

### Migration path

If a script or runbook references `smbpasswd.py`, the migration to `changepasswd.py` is mechanical:

| Old smbpasswd.py invocation | Equivalent changepasswd.py invocation |
|:---|:---|
| `smbpasswd.py DOMAIN/user@host` | `changepasswd.py DOMAIN/user@host -protocol smb-samr` |
| `smbpasswd.py -newpass X -hashes :YYY DOMAIN/user@host` | `changepasswd.py -newpass X -hashes :YYY -protocol smb-samr DOMAIN/user@host` |
| `smbpasswd.py -resetuser alice -newpass X DOMAIN/admin:pass@host` | `changepasswd.py -altuser alice -newpass X -reset -protocol smb-samr DOMAIN/admin:pass@host` |

The `-protocol smb-samr` explicit selection is optional because it's the default, but making it explicit improves script readability.



## Further reading

- **Impacket smbpasswd.py source** at `https://github.com/fortra/impacket/blob/master/examples/smbpasswd.py`.
- **snovvcrash "Pretending to be smbpasswd with Impacket"** (October 2020) at `https://snovvcrash.github.io/2020/10/31/pretending-to-be-smbpasswd-with-impacket.html`. The blog post that introduced the tool. Essential historical reading.
- **n00py "Resetting Expired Passwords Remotely"** (September 2021) at `https://www.n00py.io/2021/09/resetting-expired-passwords-remotely/`. The research that documented the SAMR-vs-logon expired-password distinction smbpasswd exploits.
- **PR #381** at `https://github.com/fortra/impacket/pull/381` for the NTLM hash as new password support.
- **PR #1177** at `https://github.com/fortra/impacket/pull/1177` for Kerberos authentication support by p0dalirius.
- **PR #1207** at `https://github.com/fortra/impacket/pull/1207` for the reset password additions by stephenbradshaw.
- **PR #1559** at `https://github.com/fortra/impacket/pull/1559` for the consolidation into changepasswd.py.
- **Samba smbpasswd.c source** at `https://github.com/samba-team/samba/blob/master/source3/utils/smbpasswd.c` for the original namesake tool.
- **`[MS-SAMR]` specification** at `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/`.
- **[`changepasswd.py`](changepasswd.md) wiki article** for the full unified-tool coverage that supersedes this script.

If you want to internalize smbpasswd.py as a tool, the exercise is simple because the scope is narrow: run it once in a lab to change your own password, and observe that the event log shows 4723 and the network traffic shows SAMR over SMB. That's the whole tool. Then run the equivalent changepasswd.py invocation with `-protocol smb-samr` and observe identical behavior. Then read the changepasswd.py article and focus on the protocols smbpasswd does NOT support (RPC SAMR, kpasswd, LDAP) to understand what you gain by switching. The practical outcome of this exercise is confidence that migrating existing smbpasswd integrations to changepasswd is safe and low risk. smbpasswd was an important tool in its era; changepasswd is its successor. Documenting both completes the historical record while making the current recommendation clear.
