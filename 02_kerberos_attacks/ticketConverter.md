
title: "ticketConverter.py"
script: "examples/ticketConverter.py"
category: "Kerberos Attacks"
status: "Published"
protocols:
  - Kerberos
ms_specs:
  - MS-KILE
ietf_specs:
  - RFC 4120
mitre_techniques:
  - T1550.003
  - T1558
auth_types:
  - none
tags:
  - impacket
  - impacket/examples
  - category/kerberos
  - status/published
  - protocol/kerberos
  - ms-spec/ms-kile
  - technique/ticket_format_conversion
  - technique/cross_tool_interop
  - mitre/T1550.003
  - mitre/T1558
aliases:
  - ticketconverter
  - impacket-ticketconverter
  - ticket_converter


# ticketConverter.py

> **One line summary:** Bidirectional converter that detects format automatically for Kerberos ticket files between the two ubiquitous storage formats: ccache (the MIT Kerberos credential cache format used by Impacket and other Kerberos tooling on Linux and across platforms) and kirbi (the binary KRB-CRED ASN.1 message format used natively by Windows tools like mimikatz, Rubeus, and kekeo); the script reads the input file, detects which format it is by examining the byte signatures (ccache starts with magic version bytes, kirbi starts with the ASN.1 tag for KRB-CRED), and writes the converted output to the second positional argument; authored by Zer1t0 (`@Zer1t0`), originally as the standalone `ticket_converter.py` project, then upstreamed into Impacket as `examples/ticketConverter.py`; the tool requires no network connectivity, no credentials, no domain context whatsoever, since it operates purely on local file format conversion via the impacket.krb5.ccache and impacket.krb5.asn1 modules; serves as the essential interoperability bridge between Impacket workflows on Linux and Rubeus/mimikatz workflows on Windows in any engagement spanning both platforms; continues Kerberos Attacks at 7 of 9 articles, putting the category at 78% complete.

| Field | Value |
|:---|:---|
| Script | `examples/ticketConverter.py` |
| Category | Kerberos Attacks |
| Status | Published |
| Author | Zer1t0 (`@Zer1t0`); upstreamed into Impacket from the standalone `ticket_converter` project |
| Primary protocol | None (local file conversion only) |
| Primary Microsoft specifications | `[MS-KILE]` Kerberos Protocol Extensions (kirbi format originates here) |
| Relevant IETF references | RFC 4120 Kerberos V5 (defines KRB-CRED message); MIT Kerberos ccache file format documentation |
| MITRE ATT&CK techniques | T1550.003 Use Alternate Authentication Material: Pass the Ticket (the workflow ticketConverter enables), T1558 Steal or Forge Kerberos Tickets (parent category) |
| Authentication types supported | None required - operates on local files |
| Network requirement | None |



## Prerequisites

This article is intentionally short and depends on cross references rather than reexplaining theory. Read first:

- [`getTGT.py`](getTGT.md) for ccache format basics, KRB5CCNAME environment variable, and where Impacket-issued tickets live.
- [`ticketer.py`](ticketer.md) for ticket forgery context (Golden and Silver Tickets are written to disk in ccache format by default, and the question "how do I use this on a Windows host" is answered by ticketConverter).
- [`getPac.py`](getPac.md) and [`getST.py`](getST.md) for additional context on the ticket types that may need conversion (TGT, TGS, S4U-derived service tickets).
- [`00_Introduction_and_Architecture.md`](Introduction_and_Architecture.md) for the overall Impacket architecture.



## What it does

`ticketConverter.py` takes a Kerberos ticket file in one format and writes the equivalent file in the other format:

```text
$ ticketConverter.py admin.ccache admin.kirbi
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies
[*] converting ccache to kirbi...
[+] done

$ ticketConverter.py admin.kirbi admin.ccache
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies
[*] converting kirbi to ccache...
[+] done
```

The tool's defining characteristics:

- **Detection of format is automatic.** No flag is needed to specify direction. The script reads the first few bytes of the input file and identifies the format by magic signature (ccache starts with `0x05` version bytes; kirbi starts with the ASN.1 outer tag of a KRB-CRED structure).
- **Two positional arguments.** Input file, output file. That's the entire CLI.
- **Stateless.** No domain context, no credentials, no network. Pure local file conversion.
- **Lossless in both directions.** All ticket fields, encryption keys, flags, and validity timestamps are preserved.

The simplicity is the point. ticketConverter is not a sophisticated tool; it's a glue utility that solves one specific interop problem across platforms cleanly.



## Why it exists

The Kerberos ecosystem has two dominant ticket storage formats, originating from two dominant tooling lineages:

- **ccache (credential cache)**, defined by MIT Kerberos. Used by `kinit`, `klist`, `kdestroy`, every Linux Kerberos client, every Kerberos library that runs across platforms (including Heimdal), and nearly every offensive Linux tool including all of Impacket. The KRB5CCNAME environment variable points at a ccache file (or a collection name like KEYRING:, KCM:, etc.).
- **kirbi (KRB-CRED message dumped to disk)**, originating from Microsoft's Windows Kerberos implementation. Used natively by mimikatz (`kerberos::ptt <file.kirbi>`), Rubeus (`/ticket:<base64>.kirbi`), kekeo, and a long lineage of Kerberos research tools running on Windows.

Both formats encode the same underlying data (the KRB-CRED structure plus the encryption keys needed to decrypt the ticket's enc-part). They differ in their wrapping:

- **ccache** wraps tickets in a custom binary file format with header, principal records, credential blocks, and timestamp fields. Designed for multi-ticket caches.
- **kirbi** is the raw ASN.1 DER encoding of the KRB-CRED protocol message. Designed as an export format holding one ticket.

Converting between them is a routine need in any engagement that crosses platform boundaries:

- Forge a Golden Ticket on Linux with `ticketer.py` (which produces a ccache), then move to a Windows host and import via `mimikatz # kerberos::ptt admin.kirbi`. Requires ccache → kirbi conversion.
- Steal a TGT from a Windows host with `Rubeus.exe dump` (which produces base64 kirbi), then move to a Linux host to use with Impacket's `psexec.py -k`. Requires kirbi → ccache conversion.
- Run S4U2Self with `getST.py -impersonate` on Linux (produces ccache), then use that ticket from a Windows host. ccache → kirbi.
- Capture a ticket via mimikatz `sekurlsa::tickets /export` (produces kirbi files), then process with Impacket's getST or other tools on Linux. kirbi → ccache.

Before ticketConverter, this conversion required custom scripts or manual ASN.1 manipulation. Zer1t0 wrote the standalone `ticket_converter.py` to solve the problem cleanly, and the tool was upstreamed into Impacket as `examples/ticketConverter.py` so every engagement using Impacket has the converter available without extra dependencies.

The tool is small (~150 lines) and does exactly one thing well. This is in the Unix tradition: small, composable, focused.



## Format theory

This section covers the minimum needed to understand what the conversion is actually doing. For deeper Kerberos protocol theory, see [`getTGT.py`](getTGT.md) and [`ticketer.py`](ticketer.md).

### KRB-CRED (RFC 4120 section 5.8)

KRB-CRED is the Kerberos protocol message designed for transferring credentials between processes or principals. Its ASN.1 structure (simplified):

```text
KRB-CRED ::= SEQUENCE {
    pvno      [0] INTEGER (5)
    msg-type  [1] INTEGER (22)
    tickets   [2] SEQUENCE OF Ticket
    enc-part  [3] EncryptedData
}
```

Where `enc-part` decrypts to:

```text
EncKrbCredPart ::= SEQUENCE {
    ticket-info [0] SEQUENCE OF KrbCredInfo
    ...
}

KrbCredInfo ::= SEQUENCE {
    key      [0] EncryptionKey
    prealm   [1] Realm
    pname    [2] PrincipalName
    flags    [3] TicketFlags
    authtime [4] KerberosTime
    starttime [5] KerberosTime
    endtime  [6] KerberosTime
    renew-till [7] KerberosTime
    srealm   [8] Realm
    sname    [9] PrincipalName
    caddr    [10] HostAddresses
}
```

The KRB-CRED message contains both the ticket itself (encrypted to the service's key, which the holder cannot decrypt) AND the session key needed to use it (in the enc-part, encrypted to a key the holder knows). When you "have a ticket," you really need both pieces.

When this structure is encoded as DER and written to a file, you get a kirbi file. The name comes from KRB (the Kerberos message family) plus an arbitrary abbreviation internal to Microsoft.

### MIT ccache format

ccache is the MIT Kerberos credential cache file format. Documented at `http://web.mit.edu/KERBEROS/krb5-devel/doc/formats/ccache_file_format.html`. Structure:

```text
File header:
    version (2 bytes, e.g. 0x0504 for v4)
    header length (2 bytes)
    header data (e.g. KDC time offset)
Default principal:
    principal record (name type + components)
Credential records (one per ticket):
    client principal
    server principal
    keyblock
    timestamps (authtime, starttime, endtime, renew_till)
    is_skey flag
    ticket flags
    addresses
    authdata
    ticket (raw DER-encoded Ticket)
    second_ticket (rare, used in some protocols)
```

The ccache format is designed to hold MULTIPLE tickets (one default principal plus many credentials for various services). A ccache holding only a single ticket is just a degenerate case with one credential entry.

### What conversion entails

Converting a kirbi (single KRB-CRED message) to a ccache (file with header + default principal + credential records) requires:

1. Parse the kirbi: DER-decode the outer KRB-CRED, decrypt enc-part to get EncKrbCredPart, extract the KrbCredInfo and the Ticket.
2. Create a ccache file structure: write version header, set the default principal from the KrbCredInfo's pname/prealm.
3. Build a Credential record from the KrbCredInfo data (keyblock from key, timestamps from authtime/starttime/etc.) plus the Ticket bytes.
4. Write to disk.

The reverse direction (ccache → kirbi):

1. Parse the ccache: read header, default principal, iterate credential records, pick one (typically the first, since most ccache files used by Impacket contain only one ticket).
2. Build a KrbCredInfo from the credential's data.
3. Wrap in EncKrbCredPart, encrypt or leave plaintext (Windows accepts plaintext enc-part for kirbi exports).
4. Wrap in a KRB-CRED outer structure with the original Ticket.
5. DER-encode and write to disk.

The conversion is mechanical bytewise translation. No Kerberos protocol exchange happens. No KDC is contacted. The tool just reformats existing data.

### Why "kirbi" and "ccache"

Trivia worth knowing:

- "ccache" stands for **c**redential **cache**. MIT Kerberos terminology, in use since the original v5 implementation in the early 1990s.
- "kirbi" is an abbreviation internal to Microsoft that escaped via Benjamin Delpy's mimikatz and entered popular use through that channel. There is no official Microsoft documentation explaining the etymology; the format is just "KRB-CRED dumped to disk" and Microsoft tools have been using `.kirbi` as the file extension for this format for many years.
- Both Rubeus and mimikatz also support a base64-encoded kirbi format (handy for shell-friendly ticket pasting). Some derivative tools like `RubeusToCcache` exist specifically to handle the base64 form. ticketConverter does NOT handle base64 directly; you have to base64-decode first.

### Why two formats exist

Both communities (MIT Kerberos and Microsoft Kerberos) developed their tooling independently. Each picked a sensible format for their use case:

- MIT needed a multi-ticket cache for users with many service tickets. ccache fits.
- Microsoft needed an export format holding one ticket for credential transfer scenarios. KRB-CRED written as a file fits.

There is no good technical reason both formats exist; they're just different lineages converging on the same problem from different directions. ticketConverter is the bridge between them.



## How the tool works internally

The script is intentionally simple. About 150 lines.

### Imports

```python
from impacket.krb5.ccache import CCache, Header, Principal, Credential, \
    KeyBlock, Times, CountedOctetString
from impacket.krb5.asn1 import KRB_CRED, EncKrbCredPart, Ticket, \
    seq_set, seq_set_iter, KrbCredInfo, EncryptionKey
from pyasn1.codec.der import decoder, encoder
```

The script leans entirely on Impacket's existing ccache and ASN.1 modules. The conversion is reformatting between representations held in memory.

### Flow

1. **Parse arguments.** `input_file` and `output_file` (positional).

2. **Detect input format.** Read first bytes:
   - If they match a ccache header signature (e.g. `0x05` followed by version), it's a ccache.
   - If they match the ASN.1 outer tag for KRB-CRED (`0x76` for an APPLICATION 22 tag with constructed bit set), it's a kirbi.
   - Otherwise, error out.

3. **Dispatch to converter.**
   - `convert_ccache_to_kirbi(input, output)`, or
   - `convert_kirbi_to_ccache(input, output)`.

4. **Convert and write.**

### kirbi → ccache implementation

```python
def convert_kirbi_to_ccache(kirbi_file, ccache_file):
    # Parse the kirbi
    with open(kirbi_file, 'rb') as f:
        kirbi_data = f.read()
    krb_cred = decoder.decode(kirbi_data, asn1Spec=KRB_CRED())[0]
    
    # Decrypt enc-part to get EncKrbCredPart (typically plaintext for exports)
    enc_part_data = krb_cred['enc-part']['cipher']
    enc_krb_cred_part = decoder.decode(enc_part_data, asn1Spec=EncKrbCredPart())[0]
    
    # Extract the first ticket-info entry (most kirbi files contain just one)
    krb_cred_info = enc_krb_cred_part['ticket-info'][0]
    ticket = krb_cred['tickets'][0]
    
    # Build a CCache object
    ccache = CCache()
    ccache.headers.append(...)
    ccache.principal = Principal(<from krb_cred_info['pname']>)
    
    # Build the Credential
    credential = Credential()
    credential['client'] = ...
    credential['server'] = ...
    credential['key'] = KeyBlock(<from krb_cred_info['key']>)
    credential['time'] = Times(<from authtime/starttime/endtime/renew_till>)
    credential['ticket'] = encoder.encode(ticket)
    
    ccache.credentials.append(credential)
    ccache.saveFile(ccache_file)
```

(Pseudocode, real implementation has more details around principal name component handling and timestamp conversion.)

### ccache → kirbi implementation

```python
def convert_ccache_to_kirbi(ccache_file, kirbi_file):
    ccache = CCache.loadFile(ccache_file)
    credential = ccache.credentials[0]  # first credential, typically the only one
    
    # Build KrbCredInfo from the credential
    krb_cred_info = KrbCredInfo()
    krb_cred_info['key'] = EncryptionKey(<from credential['key']>)
    krb_cred_info['prealm'] = ...
    krb_cred_info['pname'] = ...
    krb_cred_info['flags'] = ...
    krb_cred_info['authtime'] = ...
    # etc.
    
    # Build EncKrbCredPart wrapping it
    enc_krb_cred_part = EncKrbCredPart()
    enc_krb_cred_part['ticket-info'][0] = krb_cred_info
    
    # Build outer KRB-CRED
    krb_cred = KRB_CRED()
    krb_cred['pvno'] = 5
    krb_cred['msg-type'] = 22
    krb_cred['tickets'][0] = decoder.decode(credential['ticket'], asn1Spec=Ticket())[0]
    krb_cred['enc-part']['etype'] = 0  # plaintext for export
    krb_cred['enc-part']['cipher'] = encoder.encode(enc_krb_cred_part)
    
    # Write to disk
    with open(kirbi_file, 'wb') as f:
        f.write(encoder.encode(krb_cred))
```

The "encryption" of enc-part in exported kirbi files is typically plaintext (etype 0), because the export is for client-side ticket transfer where the holder needs the session key directly. Mimikatz, Rubeus, and Windows LSA all accept this convention.

### What the tool does NOT do

- Does not validate the ticket. A corrupt or invalid ticket will convert successfully and produce a corrupt output.
- Does not modify the ticket. No encryption changes, no field rewrites, no signature regeneration.
- Does not handle base64-encoded kirbi. Use `base64 -d` first if your kirbi is base64 (as Rubeus output often is).
- Does not handle multi-ticket ccaches well in the kirbi direction. Only the first credential is converted. If your ccache has multiple tickets, only one survives the round trip.



## Authentication options

None required. The tool is purely local file manipulation.



## Practical usage

### Convert a TGT obtained on Linux to kirbi importable on Windows

```bash
# Step 1: Get a TGT on Linux with Impacket
getTGT.py ACME.LOCAL/alice:Passw0rd!
# Output: alice.ccache

# Step 2: Convert to kirbi for Windows use
ticketConverter.py alice.ccache alice.kirbi

# Step 3: Move alice.kirbi to a Windows host (e.g. via SMB, scp, encoded in stego)
# Step 4: On Windows, use with mimikatz or Rubeus
#   mimikatz # kerberos::ptt alice.kirbi
#   .\Rubeus.exe ptt /ticket:alice.kirbi
```

Classic pivot across platforms. Linux for Kerberos manipulation, Windows for actual interactive use.

### Convert a ticket stolen on Windows to ccache usable on Linux

```bash
# Step 1: On Windows, capture a ticket
#   .\Rubeus.exe dump /service:krbtgt /nowrap
# Output: base64-encoded kirbi blob in console

# Step 2: Decode the base64 to a binary kirbi
echo "<base64 string>" | base64 -d > admin.kirbi

# Step 3: Convert to ccache
ticketConverter.py admin.kirbi admin.ccache

# Step 4: Use with Impacket
export KRB5CCNAME=admin.ccache
psexec.py -k -no-pass ACME.LOCAL/administrator@dc01.acme.local
```

Ticket theft on Windows, ticket use on Linux. The classic offensive Kerberos pipeline.

### Convert a forged Golden Ticket from ticketer.py to kirbi

```bash
# Step 1: Forge a Golden Ticket on Linux
ticketer.py -nthash <krbtgt-hash> \
            -domain-sid S-1-5-21-... \
            -domain ACME.LOCAL \
            administrator
# Output: administrator.ccache

# Step 2: Convert for Windows use
ticketConverter.py administrator.ccache administrator.kirbi

# Step 3: Import on a Windows host with mimikatz
#   mimikatz # kerberos::ptt administrator.kirbi
```

Forge on Linux (cleaner Python tooling, easier scripting), use on Windows (interactive RDP, persistent injection).

### Convert a Sapphire Ticket for Windows interactive use

```bash
# Step 1: Build a Sapphire Ticket on Linux (combines getPac under the hood)
ticketer.py -impersonate administrator \
            -nthash <krbtgt-hash> \
            -domain-sid S-1-5-21-... \
            -domain ACME.LOCAL \
            administrator
# Output: administrator.ccache (contains real PAC via S4U2Self+U2U)

# Step 2: Convert
ticketConverter.py administrator.ccache administrator-sapphire.kirbi

# Step 3: Use on Windows
#   .\Rubeus.exe ptt /ticket:administrator-sapphire.kirbi
```

Stealthy tickets benefit from use on Windows because subsequent activity from the Windows host looks more legitimate to detection at the network layer than activity from a Linux attack host.

### Round trip a ticket for verification

```bash
ticketConverter.py original.ccache temp.kirbi
ticketConverter.py temp.kirbi roundtrip.ccache
diff <(klist -k original.ccache 2>/dev/null) <(klist -k roundtrip.ccache 2>/dev/null)
```

Sanity check that the conversion is lossless. Useful when debugging weird Kerberos behavior to rule out corruption from the format conversion as the cause.

### Key flags

| Flag | Meaning |
|:---|:---|
| `input_file` (positional) | Source file in either kirbi or ccache format. Detected automatically. |
| `output_file` (positional) | Destination file in the opposite format. |

That's the entire flag surface. Two arguments. No options. The tool does one thing.



## What it looks like on the wire

Nothing. The tool is purely local file manipulation. No network traffic.



## What it looks like in logs

Nothing on remote hosts. The tool runs entirely locally; if the operator has filesystem audit logging on the attacker host (rare), file read/write events would appear, but no events fire on the domain side.

The downstream uses of the converted ticket (importing it on a Windows host with mimikatz, using it with psexec.py, etc.) generate the typical Kerberos and authentication logs for those subsequent operations. Those events look identical regardless of whether the ticket was converted via ticketConverter or any other means.

This makes ticketConverter.py invisible to all standard detection mechanisms. The conversion itself leaves no detectable trace; only the use of the resulting ticket leaves traces.



## Detection and defense

### Detection opportunities

There are essentially none for the conversion step itself. The tool runs locally, touches no network, requires no credentials, generates no logs.

Detection focuses entirely on the upstream and downstream operations:

- **Upstream**: how was the ticket obtained? `ticketer.py` for forgery, `getTGT.py` for legitimate authentication, `getST.py` for service ticket retrieval, `getPac.py` + ticketer for Sapphire. All have their own detection signatures (see those articles).
- **Downstream**: how is the converted ticket used? Pass the Ticket on Windows (via mimikatz `kerberos::ptt` or Rubeus `ptt`), or via Impacket tools on Linux (`psexec.py -k`, `wmiexec.py -k`, etc.). Each generates the standard Kerberos logon and service ticket events for the eventual access.

### Preventive controls

For ticketConverter specifically: none possible. The tool operates on local files controlled by the attacker outside any defender's reach.

For the broader Pass the Ticket workflow that ticketConverter enables:

- **Detect anomalous TGT usage.** Tickets used from machines that did not previously have an active session for the user can indicate Pass the Ticket.
- **Detect Pass the Ticket via Event 4624 patterns.** Logon Type 3 (Network) with Authentication Package = Kerberos, originating from unusual sources.
- **MDI Pass the Ticket detection** is the highest-fidelity option where deployed.
- **Tier 0 isolation** limits the use of stolen Tier 0 tickets even when conversion succeeds.

### What ticketConverter.py does NOT do

- Does NOT validate or check ticket integrity.
- Does NOT decrypt the ticket itself (only the enc-part wrapping the session key).
- Does NOT modify the ticket payload (encrypted with the service or krbtgt key, opaque to converter).
- Does NOT contact a KDC.
- Does NOT need credentials.
- Does NOT generate any network traffic.
- Does NOT handle base64-encoded input directly.
- Does NOT support multi-ticket ccaches well (only first credential converts).



## Related tools and attack chains

`ticketConverter.py` continues Kerberos Attacks at **7 of 9 articles, putting the category at 78% complete** with only `kintercept.py` remaining for full closure.

### Related Impacket tools

- [`getTGT.py`](getTGT.md) produces ccache files that ticketConverter can transform to kirbi for use on Windows.
- [`getST.py`](getST.md) produces service tickets in ccache format. Same pattern.
- [`ticketer.py`](ticketer.md) writes Golden, Silver, and Sapphire Tickets to ccache by default. ticketConverter is the natural follow up for Windows deployment.
- [`getPac.py`](getPac.md) produces structural information about PAC contents, not ticket files directly. But the Sapphire Tickets it enables (via ticketer.py `-impersonate`) frequently need ticketConverter for Windows use.
- [`raiseChild.py`](raiseChild.md) writes the Golden Ticket spanning domains to ccache. Same conversion need for use on Windows.
- [`keylistattack.py`](keylistattack.md) extracts hashes, not tickets. Unrelated to ticketConverter directly but part of the same Kerberos toolkit.

### External alternatives

- **`zer1t0/ticket_converter`** at `https://github.com/zer1t0/ticket_converter`. The original standalone version of this tool, which was upstreamed into Impacket. Functionally identical; the standalone version is occasionally updated independently.
- **`SolomonSklash/RubeusToCcache`** at `https://github.com/SolomonSklash/RubeusToCcache`. Specifically handles Rubeus's base64-encoded kirbi output, performing the base64 decode plus the kirbi-to-ccache conversion in one step. Useful when piping Rubeus output through automation.
- **`KrbCredExport`** by rvazarkar at `https://github.com/rvazarkar/KrbCredExport`. Earlier prior art tool for the same problem, referenced in ticketConverter's source comments.
- **mimikatz** can read ccache files directly via certain commands (`kerberos::list /export` and similar) but the format support varies by version. ticketConverter is more reliable for work crossing between formats.
- **kekeo** by Benjamin Delpy at `https://github.com/gentilkiwi/kekeo`. Older Kerberos utility for Windows with various format manipulation capabilities including some ccache support.

For a Linux operator working with Impacket, ticketConverter.py is the right tool. For a Windows operator dealing with Rubeus output, RubeusToCcache may save a step. For everything else, this is the canonical conversion utility.

### Pass the Ticket workflow across platforms

```mermaid
flowchart LR
    A[Linux: ticket source] --> B[ccache file]
    B --> C[ticketConverter.py]
    C --> D[kirbi file]
    D --> E[Transfer to Windows]
    E --> F[mimikatz / Rubeus]
    F --> G[Pass the Ticket]
    
    H[Windows: ticket source] --> I[base64 kirbi from Rubeus]
    I --> J[base64 -d]
    J --> K[binary kirbi]
    K --> L[ticketConverter.py]
    L --> M[ccache file]
    M --> N[Transfer to Linux]
    N --> O[Impacket -k -no-pass]
    O --> G
```

The flowchart highlights ticketConverter's role as the format bridge in either direction. Both arrows converge on the same outcome: Pass the Ticket using a stolen or forged credential on the platform where it is most operationally useful.

### When to use ticketConverter

The decision flowchart is simple: if you have a ticket file in one format and need it in the other, use ticketConverter. There is no "advanced operator chooses something else" alternative that is meaningfully better for routine use. The tool is the right answer for the use case.

The only exceptions:

- If the input is base64-encoded kirbi, decode it first or use RubeusToCcache.
- If the ccache has multiple tickets that all matter, you may need to extract them separately first.
- If the ticket needs modification (re-signing, PAC manipulation, validity extension), use ticketer.py with the appropriate flags rather than converting and editing.



## Further reading

- **RFC 4120: Kerberos Network Authentication Service (V5).** Section 5.8 defines KRB-CRED.
- **MIT Kerberos ccache file format documentation** at `http://web.mit.edu/KERBEROS/krb5-devel/doc/formats/ccache_file_format.html`. The canonical reference for the ccache binary layout.
- **`[MS-KILE]`: Kerberos Protocol Extensions** at `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/`. Contains Microsoft-specific Kerberos behavior including some kirbi semantics.
- **Impacket ticketConverter.py source** at `https://github.com/fortra/impacket/blob/master/examples/ticketConverter.py`. About 150 lines, very readable.
- **Zer1t0's original ticket_converter** at `https://github.com/zer1t0/ticket_converter`. The pre-Impacket standalone version.
- **RubeusToCcache** at `https://github.com/SolomonSklash/RubeusToCcache`. Base64-aware variant for Rubeus pipelines.
- **"Experimenting with Kerberos Ticket Formats"** by tw1sm at `https://tw1sm.github.io/2021-02-01-kerberos-conversion/`. Hands-on walkthrough of moving tickets between Rubeus, Impacket, mimikatz, and CrackMapExec.
- **MITRE ATT&CK T1550.003 Pass the Ticket** at `https://attack.mitre.org/techniques/T1550/003/`. The technique ticketConverter enables.

The tool is small enough that the source itself is the best reference. About 150 lines of Python, broken into roughly equal halves for the two conversion directions. Reading it once internalizes the entire Impacket ccache and KRB-CRED handling pattern, which is useful background for anyone debugging Kerberos issues in Impacket-based workflows. The shortest exercise: get any ticket, convert it both directions, run `klist -k <ccache>` on each variant and confirm the timestamps and principal match. If you can do that round trip cleanly, you have effectively mastered the tool. There is no deeper magic to discover.
