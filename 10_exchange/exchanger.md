
title: "exchanger.py"
script: "examples/exchanger.py"
category: "Exchange"
status: "Published"
protocols:
  - MS-RPCH
  - MS-NSPI
  - MS-OXNSPI
  - MS-OXABREF
  - NTLM
  - HTTP
  - HTTPS
ms_specs:
  - MS-RPCH
  - MS-NSPI
  - MS-OXNSPI
  - MS-OXABREF
  - MS-NLMP
mitre_techniques:
  - T1087.003
  - T1087.002
  - T1213.002
  - T1078
auth_types:
  - password
  - nt_hash
  - basic_auth
tags:
  - impacket
  - impacket/examples
  - category/exchange
  - status/published
  - protocol/rpch
  - protocol/nspi
  - protocol/oxnspi
  - protocol/oxabref
  - protocol/http
  - authentication/ntlm
  - authentication/basic_auth
  - technique/gal_enumeration
  - technique/address_book_dump
  - technique/exchange_enumeration
  - technique/rpc_over_http
  - mitre/T1087/003
  - mitre/T1087/002
  - mitre/T1213/002
  - mitre/T1078
aliases:
  - exchanger
  - impacket-exchanger


# exchanger.py

> **One line summary:** Tool for connecting to Microsoft Exchange servers via RPC over HTTP v2 (MS-RPCH) to abuse the Name Service Provider Interface (MS-NSPI / MS-OXNSPI / MS-OXABREF), which is the Outlook client's interface for querying Exchange Address Books; authorized with any valid domain user account (no mailbox required, no elevated privilege needed), the tool enumerates and dumps the complete Global Address List along with all distribution lists, contact tables, and Distinguished Name Tag (DNT) mappings, yielding a comprehensive roster of every user, group, distribution list, and mail-enabled contact in the organization along with rich metadata (email, title, manager, phone, office location, department, employee ID) that is invaluable for reconnaissance, social engineering, password spraying target list construction, and **org chart reconstruction from the outside** when only a single low-privileged credential is available; written by Arseniy Sharoglazov (`@mohemiv`) at Positive Technologies and opens the Exchange category as the first of one planned articles in that category.

| Field | Value |
|:---|:---|
| Script | `examples/exchanger.py` |
| Category | Exchange |
| Status | Published |
| Primary protocols | MS-RPCH (RPC over HTTP v2), MS-NSPI / MS-OXNSPI / MS-OXABREF (Exchange address book RPC interfaces), NTLM, HTTP/HTTPS |
| Primary Microsoft specifications | `[MS-RPCH]`, `[MS-NSPI]`, `[MS-OXNSPI]`, `[MS-OXABREF]`, `[MS-NLMP]` |
| MITRE ATT&CK techniques | T1087.003 Account Discovery: Email Account, T1087.002 Account Discovery: Domain Account, T1213.002 Data from Information Repositories: Sharepoint (close parallel for Exchange), T1078 Valid Accounts |
| Authentication types supported | Password, NT hash, Basic Auth |
| First appearance in Impacket | Impacket 0.9.22 (November 2020, as part of PR #912 which added MS-RPCH v2, MS-NSPI, MS-OXNSPI, and MS-OXABREF implementations) |
| Original author | Arseniy Sharoglazov (`@mohemiv`) / Positive Technologies |



## Prerequisites

This article builds on:

- [`00_Introduction_and_Architecture.md`](Introduction_and_Architecture.md) for the Impacket stack overview.
- [`rpcdump.py`](../01_recon_and_enumeration/rpcdump.md) for DCE/RPC fundamentals. Exchanger uses MS-RPCH as a transport, which layers DCE/RPC on top of HTTP instead of the more familiar SMB or TCP transports.
- [`samrdump.py`](../01_recon_and_enumeration/samrdump.md) for the general pattern of RPC based enumeration. Exchanger does the Exchange version of this: enumerate objects over a specific RPC interface.

Familiarity with Microsoft Exchange architecture helps but is not required. The article explains the relevant Exchange concepts from the ground up.



## What it does

`exchanger.py` is a command line tool for extracting information from Microsoft Exchange servers via the Name Service Provider Interface (NSPI), the RPC interface that Outlook itself uses to query Exchange Address Books. The tool currently exposes one module (`nspi`) with three submodules:

| Submodule | Purpose |
|:---|:---|
| `list-tables` | Enumerate all Address Book containers (tables) visible to the authenticated user. |
| `dump-tables` | Dump the contents of Address Book containers (the Global Address List, distribution lists, public folders, user tables). |
| `dnt-lookup` | Look up Distinguished Name Tags (DNTs), which are numeric identifiers for address book objects, to reveal the corresponding distinguished names and attributes. |

Running the `dump-tables` submodule against a typical enterprise Exchange deployment produces a catalog of every user, contact, distribution list, and mail enabled object in the organization. For each object, the tool can return attributes such as:

- Display name, first name, last name.
- Email address (primary and proxy).
- Job title, department, company, manager.
- Office location, street address, country.
- Phone numbers (work, mobile, fax).
- Employee ID.
- Distinguished Name within the Exchange topology.
- Manager and direct reports references.

This is rich reconnaissance data obtainable with a single low privileged user account.

The tool works against:

- **On premises Exchange Server** (2013, 2016, 2019, Subscription Edition) with RPC over HTTP (also known as Outlook Anywhere) enabled. This is the most common configuration for organizations that support Outlook clients accessing Exchange over the Internet or across network boundaries.
- **Hybrid Exchange** deployments where an on premises server sits alongside Exchange Online.
- **Any Exchange proxy endpoint** reachable from the attacker's position, including the internal network, the DMZ, or Internet facing hosts.

It does not work against:

- **Pure Exchange Online (Microsoft 365) without a hybrid on premises component.** Exchange Online uses different protocols (primarily Graph API and MAPI over HTTPS with modern authentication). The NSPI RPC interfaces used by exchanger are specific to on premises Exchange and hybrid deployments with RPC over HTTP enabled.
- **Exchange servers that have disabled Outlook Anywhere.** Some hardened deployments block RPC over HTTP in favor of MAPI over HTTPS only; these environments cannot be enumerated with this specific tool.

The primary operational value: Global Address List (GAL) extraction yields a complete employee roster that defeats a common defensive assumption (that internal directory data is harder to obtain than external data). Many organizations lock down Active Directory LDAP queries from untrusted networks but leave Outlook Anywhere wide open; an attacker with any domain credential can then reconstruct the entire org chart without touching LDAP.



## Why it exists

Before exchanger, Linux operators who wanted to enumerate Exchange address books either:

- Ran Outlook in a Windows VM and walked the GAL manually.
- Used PowerShell with Exchange Web Services (EWS) APIs from Windows.
- Used ruler (a Go based MAPI over HTTP client) to hit the MAPI interfaces.
- Wrote custom code against Exchange's REST APIs.

None of these worked natively on Linux with pure Python tooling.

Arseniy Sharoglazov published the "Attacking MS Exchange Web Interfaces" research at `https://swarm.ptsecurity.com/attacking-ms-exchange-web-interfaces/` in 2019-2020 documenting the attack surface of Exchange servers and specifically the NSPI interface. The research showed that NSPI is both powerful (it exposes rich address book data) and under monitored (Exchange RPC traffic is rarely scrutinized, especially when it is tunneled through HTTP).

Sharoglazov then wrote the Impacket implementations of MS-RPCH v2, MS-NSPI, MS-OXNSPI, and MS-OXABREF, and contributed `exchanger.py` as the tool that uses them. Pull request #912 merged in August 2020 and shipped in Impacket 0.9.22.

The design goals:

- Pure Python (no dependencies on Windows or ruler).
- Support for the authentication modes that Exchange actually deploys (NTLM primarily, with fallback to Basic Auth for certain configurations).
- Automatic handling of the Autodiscover flow (to determine the correct RPC endpoint from a user's mail domain).
- Enumeration of the Exchange address book with reasonable performance even against large organizations (tens of thousands of users).

The tool is currently the canonical Linux side option for Exchange GAL extraction. Related tools (ruler, MailSniper) exist but have different focus areas and trade offs.



## The protocol theory

This section covers the two protocol layers that exchanger uses: MS-RPCH (the transport) and MS-NSPI (the interface). Understanding both is essential because the tool's behavior on the wire looks different from typical DCE/RPC over SMB traffic.

### RPC over HTTP v2 (MS-RPCH)

Exchange needs to work over the Internet and across firewalls, but traditional DCE/RPC uses dynamic high ports or SMB over port 445, both of which are commonly blocked at organizational perimeters. Microsoft's solution: tunnel DCE/RPC inside HTTP/HTTPS.

The MS-RPCH protocol defines how to:

1. Establish a pair of HTTP connections (one inbound, one outbound) to an **RPC Proxy** server (typically IIS with the `RpcProxy` ISAPI extension).
2. Use these two connections as bidirectional pipes for DCE/RPC PDUs.
3. Authenticate to the RPC Proxy itself (usually with NTLM or Basic Auth over HTTPS).
4. Route subsequent DCE/RPC traffic to a backend server (typically the Exchange server, sometimes a Domain Controller).

The transport uses these specific HTTP methods:

- `RPC_IN_DATA` for the client to server channel.
- `RPC_OUT_DATA` for the server to client channel.

Each channel is a long lived HTTP request with chunked transfer encoding; the body is a continuous stream of DCE/RPC PDUs.

The architecture is deliberately firewall friendly: from the outside, all the attacker sees is two HTTPS connections to port 443. No unusual ports, no SMB signatures, nothing that a typical perimeter firewall would flag.

For Exchange deployments, the RPC Proxy URL is typically:

- `https://autodiscover.<domain>/rpc/rpcproxy.dll` (when Outlook Anywhere is enabled).
- `https://mail.<domain>/rpc/rpcproxy.dll` as an alternative.

The exchanger tool handles the MS-RPCH layer automatically. Operators typically do not need to think about the transport details beyond specifying the target URL.

### The Name Service Provider Interface (MS-NSPI / MS-OXNSPI / MS-OXABREF)

Once the MS-RPCH transport is established, exchanger binds to the NSPI interface. The interface is implemented across three related Microsoft specifications:

- **MS-NSPI** (Name Service Provider Interface): the original RPC interface for address book lookups. UUID `f5cc5a18-4264-101a-8c59-08002b2f8426`.
- **MS-OXNSPI** (Exchange Server Name Service Provider Interface): Exchange specific extensions to MS-NSPI.
- **MS-OXABREF** (Address Book Object Reference): protocol for referring to address book objects and their attributes.

Together these protocols let Outlook (or any client implementing them) query the Exchange Address Book. The Address Book is a logical view of directory data. In on premises Exchange, the address book is backed by Active Directory: every AD user with an email address appears in the GAL automatically.

The key operations exposed by NSPI:

- `NspiBind` / `NspiUnbind`: session lifecycle.
- `NspiGetSpecialTable`: retrieve special address book tables (containers).
- `NspiQueryRows`: retrieve rows from a specified table.
- `NspiGetProps`: retrieve specific properties of a specified object.
- `NspiDNToMId`: convert Distinguished Names to Minimal IDs (MIds).
- `NspiGetTemplateInfo`: retrieve schema information.
- `NspiModLinkAtt`: modify a linked attribute (writing; rarely relevant for enumeration).

The exchanger tool uses a subset focused on enumeration: `NspiBind`, `NspiGetSpecialTable`, `NspiQueryRows`, `NspiGetProps`.

### Address Book tables and containers

NSPI organizes the address book into **containers** (tables). Each container holds a set of objects. Common containers in a typical Exchange deployment:

| Container | Contents |
|:---|:---|
| **Default Global Address List** | Every mail enabled object in the organization (users, contacts, distribution lists, public folders). |
| **All Users** | Subset containing only user accounts. |
| **All Contacts** | External contacts (not employees). |
| **All Distribution Lists** | Distribution lists and dynamic groups. |
| **All Rooms** | Meeting rooms and resources. |
| **All Public Folders** | Public folders with email addresses. |
| **Offline Address Book** | The address book version distributed to Outlook clients for offline use. |
| Custom organization address lists | Organization specific custom lists (e.g., "Sales Team", "Executives", "New York Office"). |

The `list-tables` submodule enumerates these containers. The `dump-tables` submodule extracts the contents of one or more.

### Distinguished Name Tags (DNTs)

Within the Exchange directory, each object has a **Distinguished Name Tag**: a numeric identifier. DNTs are sequential integers assigned in the order objects were created; they serve as compact references within NSPI traffic.

The `dnt-lookup` submodule queries by DNT range (e.g., 500000 to 550000) to discover objects. This is useful when:

- The standard containers are locked down but specific DNT ranges are still accessible.
- Enumerating objects that are hidden from the GAL but still exist in the directory.
- Brute forcing object discovery in environments where the GAL has been trimmed.

Many Exchange environments hide certain user accounts from the GAL (often administrator accounts, service accounts, or executives) by setting `HiddenFromAddressListsEnabled` to true. DNT lookup bypasses this because DNTs exist regardless of GAL visibility; the hidden objects are still accessible if the attacker asks for them directly.

### Property lookup types

NSPI supports several property lookup modes that trade off completeness versus bandwidth. Exchanger exposes four:

| Mode | Properties returned |
|:---|:---|
| `MINIMAL` | Display name and email only. Fast. Good for quick enumeration. |
| `EXTENDED` | Above + title, department, phone, office. |
| `FULL` | Above + all queryable properties including manager and reports, employee ID, custom attributes. |
| `GUIDS` | Returns only the object GUIDs. Useful for discovering objects without pulling data. |

For most reconnaissance, `EXTENDED` is the sweet spot: enough detail for social engineering and password spraying target lists without the overhead of FULL. Operators running against very large organizations may prefer `MINIMAL` first to get a count, then selectively pull FULL data for targeted users.

### Authentication flow

The tool authenticates twice in sequence:

1. **To the RPC Proxy (IIS).** This is standard HTTP authentication. Exchange typically accepts NTLM (`-hashes` supports this) or Basic Auth (`-basic` flag). The target user must have "Outlook Anywhere" enabled on their account (default on most deployments).

2. **To the NSPI interface on the backend Exchange server.** Once MS-RPCH is established, the DCE/RPC BIND includes another authentication step. Typically the same credentials flow through automatically.

Both authentications use the supplied credentials. The tool does not support Kerberos for exchanger (no `-k` flag) because the RPC Proxy component historically had issues with Kerberos from non domain joined clients; NTLM is the reliable path.

### Why any domain user works

The key unusual property of NSPI: **any authenticated domain user with a mailbox can enumerate the GAL**. This is by design; Outlook requires this access for autocomplete and address resolution. The access is not a vulnerability; it is baseline Exchange functionality.

From a defender perspective, this means:

- Preventing GAL enumeration requires Exchange configuration changes (Address Book Policies, GAL segmentation) that break legitimate Outlook usage.
- Any credential leak (phishing, password spray, old breach data) gives the attacker the full directory.
- There is no quick defensive patch; the "fix" is architectural.

From an attacker perspective:

- A single credential yields reconnaissance data that in other contexts would require Domain Admin privileges.
- The enumeration traffic is legitimate Exchange RPC traffic, making detection difficult.
- Password spray targeting the Exchange authentication endpoint often yields at least one credential from most organizations; exchanger is the immediate follow up.



## How the tool works internally

1. **Argument parsing.** Target URL with credentials, module (currently `nspi`), submodule (`list-tables`, `dump-tables`, or `dnt-lookup`), and submodule specific options.

2. **Autodiscover or explicit RPC hostname.** If the operator did not specify `-rpc-hostname`, the tool attempts to derive the correct backend Exchange server from the target URL. If this fails, the tool exits with guidance to specify `-rpc-hostname` explicitly (which must be the internal Exchange server GUID or NetBIOS name).

3. **RPC Proxy connection.** The tool establishes the two HTTP channels (`RPC_IN_DATA` and `RPC_OUT_DATA`) to the proxy URL (typically `/rpc/rpcproxy.dll?TargetServer:6001`, where 6001 is the Exchange RPC port on the backend).

4. **NTLM / Basic Auth.** Authenticates to the RPC Proxy with the supplied credentials. Handles NTLM challenge response if default; Basic Auth if `-basic`.

5. **DCE/RPC bind to NSPI.** Once the MS-RPCH transport is up, binds to the NSPI interface UUID `f5cc5a18-4264-101a-8c59-08002b2f8426`.

6. **NspiBind.** Opens the NSPI session on the backend Exchange server. Receives a session handle.

7. **Submodule dispatch:**
    - **`list-tables`:** calls `NspiGetSpecialTable` to enumerate address book containers. Optionally calls `NspiQueryRows` on each with row count only to report total counts.
    - **`dump-tables`:** iterates through specified containers (or all if `-name` not specified). For each container, calls `NspiQueryRows` in a loop with the configured `rows-per-request` batch size, pulling all rows. For each row, calls `NspiGetProps` with the property set corresponding to the `lookup-type` (MINIMAL / EXTENDED / FULL / GUIDS).
    - **`dnt-lookup`:** iterates through a DNT range. For each DNT, calls `NspiQueryRows` or `NspiGetProps` to retrieve the object.

8. **Output formatting.** Each row is printed with a field separator. Fields like display name, email, title are listed per object. For FULL mode, many more fields appear.

9. **Session teardown.** Calls `NspiUnbind`. Closes the MS-RPCH channels.

The implementation is a few hundred lines of Python, most of which is parameter handling and output formatting. The heavy lifting is in the `impacket.dcerpc.v5.nspi` module (the NSPI protocol implementation) and the `impacket.dcerpc.v5.transport` (MS-RPCH handling).



## Authentication options

Exchanger supports NTLM password, NTLM hash, and Basic Auth. No Kerberos support.

### Cleartext password (NTLM)

```bash
exchanger.py CORP.LOCAL/alice:'Password1'@mail.corp.local nspi list-tables
```

### NT hash (NTLM pass the hash)

```bash
exchanger.py CORP.LOCAL/alice@mail.corp.local -hashes :<nthash> nspi list-tables
```

### Basic Auth

```bash
exchanger.py CORP.LOCAL/alice:'Password1'@mail.corp.local -basic nspi list-tables
```

Basic Auth is used when Exchange is configured for HTTP Basic Auth at the proxy (common in smaller deployments or when NTLM has been disabled). Requires HTTPS in production; sending Basic Auth credentials over plain HTTP is obviously unsafe and the tool will still do it if the target URL is HTTP.

### Minimum required privileges

**Any valid domain user account with a mailbox.** The account must:

- Exist in the domain.
- Have a mailbox on the Exchange server (required for NSPI binding to succeed).
- Be enabled and not require password change.

No special group memberships, no elevated privileges. The enumeration is baseline Outlook client functionality.



## Practical usage

### List available address book tables

```bash
exchanger.py CORP.LOCAL/alice:'Password1'@mail.corp.local nspi list-tables
```

Output resembles:

```text
[*] Connecting to the RPC Proxy mail.corp.local
[*] Retrieved RPC Proxy hostname via autodiscover: exch01.corp.local
[*] Bound to NSPI on exch01.corp.local

[*] Address Book Tables:
    - Default Global Address List (GUID: {...})
    - All Users
    - All Contacts
    - All Distribution Lists
    - All Rooms
    - All Public Folders
    - Offline Address Book
    - Executives
    - Sales
    - Engineering
```

### List tables with row counts

```bash
exchanger.py CORP.LOCAL/alice:'Password1'@mail.corp.local nspi list-tables -count
```

Adds a row count to each table. Useful for sizing the environment and prioritizing which tables to dump:

```text
- Default Global Address List: 8432 rows
- All Users: 5612 rows
- Executives: 12 rows
```

### Dump the entire Global Address List with MINIMAL properties

```bash
exchanger.py CORP.LOCAL/alice:'Password1'@mail.corp.local nspi dump-tables \
  -lookup-type MINIMAL
```

Without `-name`, dumps all containers. Output per user:

```text
Display Name: Alice Smith
Email: asmith@corp.local

Display Name: Bob Jones
Email: bjones@corp.local

...
```

For a typical deployment, this produces the full employee roster. Pipe to a file for later analysis:

```bash
exchanger.py ... nspi dump-tables -lookup-type MINIMAL > gal.txt
```

### Dump a specific table with EXTENDED properties

```bash
exchanger.py CORP.LOCAL/alice:'Password1'@mail.corp.local nspi dump-tables \
  -name "Executives" -lookup-type EXTENDED
```

Targets a specific container (the "Executives" custom address list). EXTENDED includes title, department, and phone. Useful for building social engineering targets focused on a specific group:

```text
Display Name: Eve Murphy
Email: emurphy@corp.local
Title: Chief Executive Officer
Department: Executive
Office: HQ, Floor 40
Phone: +1 555 0100
```

### Full property extraction

```bash
exchanger.py CORP.LOCAL/alice:'Password1'@mail.corp.local nspi dump-tables \
  -name "Default Global Address List" -lookup-type FULL > gal_full.txt
```

Pulls every available property. Much larger output, but includes manager, reports, employee ID, and all custom attributes. Useful when the goal is complete organizational reconstruction.

### DNT lookup for hidden objects

```bash
exchanger.py CORP.LOCAL/alice:'Password1'@mail.corp.local nspi dnt-lookup \
  -start-dnt 500000 -rows-per-request 100
```

Walks DNTs starting at 500000. Returns objects that exist but may be hidden from the standard GAL. Common findings include:

- Service accounts (hidden from GAL but with mailboxes).
- Executive accounts with enhanced privacy settings.
- Accounts from merged or acquired organizations.
- Disabled accounts not yet purged.

### Adjusting batch size for large organizations

```bash
exchanger.py ... nspi dump-tables -rows-per-request 50 -lookup-type MINIMAL
```

Large organizations (tens of thousands of objects) may need smaller batch sizes to avoid RPC timeouts. The default is 350 for `dnt-lookup` and 50 for `dump-tables`; increase for speed or decrease for stability.

### Key flags

| Flag | Meaning |
|:---|:---|
| `target` (positional) | `[[domain/]username[:password]@]<targetName or IP>` |
| `-rpc-hostname <name>` | Override autodiscovery of the backend Exchange server (specify by GUID or NetBIOS name). |
| `-hashes <LM:NT>` | NT hash authentication. |
| `-basic` | Basic Auth instead of NTLM. |
| `nspi list-tables -count` | Include row counts in table listing. |
| `nspi dump-tables -lookup-type <MODE>` | MINIMAL / EXTENDED / FULL / GUIDS. |
| `nspi dump-tables -name <name>` | Dump a specific table by name. |
| `nspi dnt-lookup -start-dnt <n>` | Starting DNT for the lookup range. |
| `nspi dnt-lookup -rows-per-request <n>` | Rows per NspiQueryRows call. |



## What it looks like on the wire

The traffic is HTTPS to the Exchange server, which makes network level inspection difficult. What the traffic pattern looks like:

### RPC Proxy connection establishment

Two long lived HTTPS connections to the same host (typically port 443):

- HTTP method `RPC_IN_DATA` with chunked transfer encoding. Large content length or `Transfer-Encoding: chunked`.
- HTTP method `RPC_OUT_DATA` with chunked transfer encoding.

The URLs are typically:

```text
POST /rpc/rpcproxy.dll?exch01.corp.local:6001 HTTP/1.1
```

where `exch01.corp.local` is the backend Exchange server and `6001` is the Exchange RPC port.

### Authentication

NTLM authentication appears in the HTTP Authorization headers as standard NTLM challenge response:

```text
Authorization: NTLM TlRMTVNTUAAB...
```

Basic Auth:

```text
Authorization: Basic YWxpY2U6UGFzc3dvcmQx
```

### DCE/RPC over the tunnel

Inside the HTTP bodies, standard DCE/RPC PDUs flow: BIND, BIND_ACK, REQUEST, RESPONSE. Because this is encapsulated in HTTPS, it is opaque at the network layer without TLS inspection.

### Wireshark filters

Network level detection requires TLS interception. With intercepted traffic:

```text
http.request.method == "RPC_IN_DATA"       # MS-RPCH client to server
http.request.method == "RPC_OUT_DATA"      # MS-RPCH server to client
dcerpc.if_id == f5cc5a18-4264-101a-8c59-08002b2f8426   # NSPI interface
dcerpc.pkt_type == 11                      # BIND
```

Without TLS interception, detection falls to host based signals and Exchange logs.

### Host based network signals

- The attacker host opens two HTTPS connections to the Exchange server and keeps them open for the duration of the enumeration (which can last minutes for large organizations).
- The volume of data returned can be substantial: dumping a full GAL in FULL mode for a 10000 user organization produces megabytes of decrypted HTTPS response data.



## What it looks like in logs

### IIS logs on the RPC Proxy

Every `RPC_IN_DATA` / `RPC_OUT_DATA` request appears in the IIS logs on the server hosting the RPC Proxy:

```text
2026-04-19 14:22:03 10.0.0.50 RPC_IN_DATA /rpc/rpcproxy.dll exch01.corp.local:6001 443 alice CORP 192.168.1.100 Mozilla/5.0 200 0 0 45234
```

Notable fields:

- `RPC_IN_DATA` / `RPC_OUT_DATA` as the HTTP method (unusual; most HTTP methods are GET/POST).
- The query string containing the backend target.
- The authenticated username in the `cs-username` field.
- Large response sizes when dumping tables.

### Exchange server logs

Exchange has its own RPC Client Access logs that record NSPI activity:

- `Microsoft-Exchange-HttpProxy/HttpProxy` logs on client access servers.
- RPC Client Access log entries showing NSPI method calls.

The exact log locations depend on Exchange version. For Exchange 2016/2019/SE:

```text
C:\Program Files\Microsoft\Exchange Server\V15\Logging\HttpProxy\Rpc\
C:\Program Files\Microsoft\Exchange Server\V15\Logging\RPC Client Access\
```

These logs record each NSPI method invocation with the username, timestamp, and operation type.

### Windows Security logs

Standard authentication events fire on the domain controller:

- **Event 4624** on the RPC Proxy server when the user authenticates to IIS (Logon Type 3, Network).
- **Event 4769** on the domain controller for Kerberos service ticket requests (if Kerberos was used anywhere in the flow; for exchanger specifically this is usually not applicable because exchanger uses NTLM).
- **Event 4776** on the domain controller for NTLM authentication.

### Starter Sigma rules

```yaml
title: Exchange NSPI Mass Enumeration
logsource:
  product: windows
  service: iis
detection:
  selection:
    cs-method:
      - 'RPC_IN_DATA'
      - 'RPC_OUT_DATA'
    cs-uri-stem: '/rpc/rpcproxy.dll'
  filter_legitimate:
    # Would need a whitelist of legitimate Outlook client IPs
    # (office ranges, VPN ranges, etc.) as a filter
  condition: selection and not filter_legitimate
level: medium
```

Detects any RPC over HTTP traffic. Requires tuning to exclude legitimate Outlook clients.

```yaml
title: Exchange Address Book Bulk Enumeration
logsource:
  product: windows
  service: iis
detection:
  selection:
    cs-method:
      - 'RPC_IN_DATA'
      - 'RPC_OUT_DATA'
    sc-status: 200
  timeframe: 5m
  condition: selection | count(c-ip) by cs-username > 100
level: high
```

Volume based detection. An Outlook client making 100+ requests in 5 minutes is unusual; a scripted enumeration makes many times that number of RPC requests.

```yaml
title: Exchange RPC Proxy Login from Non-Expected IP
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: 'NTLM'
    # Exchange proxy servers specifically
  filter_expected_ranges:
    IpAddress: 'expected_office_vpn_ranges'
  condition: selection and not filter_expected_ranges
level: medium
```

Catches authentication to Exchange from unusual client IPs. Environment specific tuning required.



## Detection and defense

### Detection opportunities

**Volume based anomaly detection on RPC Proxy traffic.** Outlook clients make steady background RPC traffic; exchanger makes bursts of hundreds or thousands of requests when enumerating. SIEM rules on request rate by user over short windows catch the pattern.

**Unusual IP patterns.** Outlook clients typically come from known office ranges, VPN ranges, or employee home IPs (which are at least consistent for specific users). An authentication from an unusual IP followed by heavy RPC traffic is diagnostic.

**User agent analysis.** Real Outlook clients send identifiable User Agent headers. Exchanger's default User Agent is an Impacket identifier that does not match Outlook. Not a durable signal (attackers can change User Agents), but useful until they do.

**Microsoft Defender for Identity (MDI).** MDI has detections for reconnaissance activity against domain controllers; it does not specifically cover Exchange NSPI enumeration but does catch related patterns when Exchange authentications trigger DC visibility.

**Exchange native logging analysis.** The RPC Client Access and HttpProxy logs show NSPI activity with method detail. Volume analysis on these logs catches mass enumeration patterns.

### Preventive controls

- **Address Book Policies (ABPs).** Exchange feature that segments the GAL so users only see certain subsets. If ABPs are deployed, compromised credentials yield only a partial GAL. Deployment is non trivial and breaks some Outlook autocomplete features.
- **Conditional Access for Outlook Anywhere.** Azure AD / Entra ID Conditional Access policies can require MFA or specific compliant devices for Outlook Anywhere connections. Many organizations have moved to this for Exchange Online but leave on premises unprotected.
- **Restrict Basic Auth.** Microsoft has been deprecating Basic Auth for on premises Exchange. Removing Basic Auth reduces the credential leak attack surface (only NTLM/Kerberos, which require active AD access).
- **Exchange hybrid with modern authentication.** Move to MAPI over HTTPS with OAuth tokens (rather than RPC over HTTP with NTLM). Reduces exposure to NSPI based enumeration from untrusted networks.
- **Network segmentation.** The RPC Proxy does not need to be Internet reachable in most deployments; it only needs to be reachable from where users actually Outlook from. Proper segmentation limits the attack surface.
- **Attack surface reduction.** Disable Outlook Anywhere entirely if MAPI over HTTPS is sufficient for the user base. Reduces MS-RPCH surface.
- **Monitor for authentication anomalies.** User logging in from a new country, then immediately pulling the GAL, is diagnostic. This requires UEBA capability.

### Rate limiting considerations

Exchange itself has some rate limiting on NSPI requests (to prevent abuse and protect server performance). An enumeration run in FULL mode against a large organization may trigger these limits and get throttled. This is more of a performance constraint than a security one; throttled enumerations still succeed eventually but take longer. The tool handles throttling gracefully (it retries with backoff).



## Related tools and attack chains

`exchanger.py` is currently the only article planned in the Exchange category. The category will remain at 1/1 until new Exchange related tools are added to Impacket.

### Related Impacket tools

- [`rpcdump.py`](../01_recon_and_enumeration/rpcdump.md) can also use MS-RPCH when the `-auth-transport` flag is specified. The transport implementation is the same.
- [`samrdump.py`](../01_recon_and_enumeration/samrdump.md) enumerates AD users via SAMR over SMB. Exchanger enumerates users via NSPI over HTTP. The two are complementary: samrdump works when SMB is reachable, exchanger works when Outlook Anywhere is reachable. Environments typically allow one or the other from a given attacker position.
- [`GetUserSPNs.py`](../01_recon_and_enumeration/GetUserSPNs.md) and [`findDelegation.py`](../01_recon_and_enumeration/findDelegation.md) enumerate via LDAP. For the specific goal of "get a list of all users in the domain," LDAP enumeration is the alternative. Where LDAP is blocked (common on perimeter Exchange deployments), exchanger fills the gap.

### External tools

- **ruler** at `https://github.com/sensepost/ruler`. Go based Exchange attack tool. Covers MAPI operations (email manipulation, server side rules, form based payloads) but less focused on NSPI enumeration.
- **MailSniper** at `https://github.com/dafthack/MailSniper`. PowerShell based Exchange enumeration tool. Windows side alternative.
- **PEAS (Python Exchange Attack Suite)**. Various tools for specific Exchange attack primitives.
- **CrackMapExec / nxc module for Exchange**. Does some Exchange enumeration; less feature rich than exchanger for NSPI specifically.
- **ADExplorer and BloodHound.** Parallel paths for AD enumeration; where LDAP is accessible, these are complementary.

### Attack chains

The typical chain using exchanger:

```mermaid
flowchart TD
    A[Obtain single domain user credential] --> B{Which enumeration path?}
    B -->|SMB reachable| C[samrdump.py, lookupsid.py, GetADUsers.py]
    B -->|LDAP reachable| D[GetUserSPNs.py, findDelegation.py, BloodHound]
    B -->|Only Outlook Anywhere| E[exchanger.py nspi list-tables]
    E --> F[exchanger.py nspi dump-tables -lookup-type EXTENDED]
    F --> G[Complete employee roster with titles, departments, managers]
    G --> H{Use roster for what?}
    H --> I[Password spray target list]
    H --> J[Social engineering with accurate org chart]
    H --> K[Identify privileged accounts by title]
    H --> L[Targeted phishing to executives]
    I --> M[Additional credentials]
    M --> N[Expanded access]
```

The key observation: exchanger is often the first enumeration tool because it works when LDAP and SMB do not. Perimeter Exchange servers are often the only AD adjacent service exposed to untrusted networks, and Outlook Anywhere is typically enabled for legitimate mobile and remote worker use.

### Why the Exchange attack surface matters

Exchange Server has been a primary target for years because:

- It is typically Internet exposed (at least for OWA and Outlook Anywhere).
- It runs with high privileges (often effectively local admin on the Exchange server, sometimes with broad domain privileges depending on the Exchange permission model).
- It holds sensitive data (emails, calendars, attachments).
- It has had numerous critical vulnerabilities in recent years (ProxyLogon, ProxyShell, ProxyNotShell, etc.).

Even without exploiting a vulnerability, authenticated access to Exchange via exchanger yields:

- Complete employee directory (via NSPI).
- Potentially further attack primitives if the attacker can compromise additional mailboxes via password spray.
- Context for targeted attacks based on org structure.

Exchange Online (Microsoft 365) has some of the same exposure (via Graph API and EWS), though with different tooling (MailSniper, ROADtools, etc.) needed to exploit it. The on premises Exchange attack path that exchanger covers remains relevant where hybrid or fully on premises deployments exist.



## Further reading

- **Arseniy Sharoglazov "Attacking MS Exchange Web Interfaces"** at `https://swarm.ptsecurity.com/attacking-ms-exchange-web-interfaces/`. The foundational research that motivated exchanger. Essential reading for anyone working with this tool.
- **`[MS-RPCH]`: Remote Procedure Call over HTTP Protocol** at `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpch/`. Authoritative specification for the transport.
- **`[MS-NSPI]`: Name Service Provider Interface (NSPI) Protocol** at `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nspi/`. Specification for the base NSPI interface.
- **`[MS-OXNSPI]`: Exchange Server Name Service Provider Interface (NSPI) Protocol** at `https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxnspi/`. Exchange specific extensions.
- **`[MS-OXABREF]`: Address Book Object Reference Protocol** at `https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxabref/`. Address book object reference protocol.
- **Impacket PR #912** at `https://github.com/fortra/impacket/pull/912`. The pull request that added exchanger and its protocol implementations. Includes design discussion.
- **SpecterOps "A Pentester's Guide to Cross-Domain Active Directory Attacks"** and related research. Context for how Exchange fits into broader AD attack paths.
- **Microsoft "Exchange Server 2019 Documentation: Address Lists and Address Book Policies"** at `https://learn.microsoft.com/en-us/exchange/`. Defender oriented documentation on how to segment the GAL and deploy Address Book Policies.
- **BishopFox "Pushing The Limits Of Exchange"** and related talks. Broad Exchange attack surface research.
- **MITRE ATT&CK T1087.003** at `https://attack.mitre.org/techniques/T1087/003/`. Email Account Discovery technique.
- **MITRE ATT&CK T1087.002** at `https://attack.mitre.org/techniques/T1087/002/`. Domain Account Discovery technique.

If you want to internalize exchanger, set up a lab with Exchange Server (2016 or 2019; the Evaluation edition works for 180 days). Enable Outlook Anywhere if not already enabled. Create a few test users with varied metadata (titles, departments, managers, phone numbers, office locations). From a Linux attack host, run `exchanger.py` in all three submodule variants. Observe the IIS and RPC Client Access logs on the Exchange server and note what the activity looks like from the defender's perspective. Compare the output of `dump-tables -lookup-type MINIMAL` against `-lookup-type FULL` to see what property coverage each provides. Try DNT lookup to discover objects not in the default GAL. After this exercise, the tool will feel familiar, and the defensive implications (why GAL enumeration is so accessible, why detection is hard, why the architectural answer is Address Book Policies rather than a patch) will be concrete. This context helps prioritize Exchange related controls against real threats.
