
title: "rpcdump.py"
script: "examples/rpcdump.py"
category: "Recon and Enumeration"
status: "Published"
protocols:
  - DCE/RPC
  - MSRPC
  - TCP
  - SMB (for named pipe transport)
  - RPC over HTTP
ms_specs:
  - MS-RPCE
  - MS-RPCH
  - C706 (Open Group DCE 1.1)
mitre_techniques:
  - T1046
  - T1018
auth_types:
  - null_session
  - password
  - nt_hash
tags:
  - impacket
  - impacket/examples
  - category/recon_and_enumeration
  - status/published
  - protocol/msrpc
  - protocol/dcerpc
  - protocol/tcp
  - protocol/smb
  - authentication/null_session
  - authentication/ntlm
  - technique/enumeration
  - technique/service_discovery
  - mitre/T1046
  - mitre/T1018
aliases:
  - rpcdump
  - impacket-rpcdump


# rpcdump.py

> **One line summary:** Queries the MSRPC endpoint mapper on a Windows host to enumerate every RPC service that has registered itself, returning the interface UUID, the transport binding, and a human readable annotation for each one.

| Field | Value |
|:---|:---|
| Script | `examples/rpcdump.py` |
| Category | Recon and Enumeration |
| Status | Published |
| Primary protocols | DCE/RPC, MSRPC, TCP, SMB (named pipe transport), RPC over HTTP |
| Primary Microsoft specifications | `[MS-RPCE]`, `[MS-RPCH]`, Open Group C706 |
| MITRE ATT&CK techniques | T1046 Network Service Discovery, T1018 Remote System Discovery |
| Authentication types supported | NULL session (ports 135 and 593), NTLM password, NT hash (ports 139, 445, 443) |
| First appearance in Impacket | Very early (one of the original example tools) |
| Original authors | Javier Kohen, Alberto Solino (`@agsolino`) |



## What it does

`rpcdump.py` connects to the MSRPC endpoint mapper on a target Windows host and asks it one question: "Tell me every RPC service you know about." The endpoint mapper, often shortened to **EPM**, responds with a list. Each entry in that list tells you an interface UUID that identifies a specific RPC service, the transport and address where that service is listening, and frequently a human readable name such as `Microsoft Windows Service Control Manager` or `IKE/Authip API` that tells you what the service actually does.

For a security researcher this is the reconnaissance move that happens before almost every MSRPC based attack. Every other tool in the Impacket examples folder that speaks MSRPC, and there are many, assumes the RPC service it wants to talk to is reachable. `rpcdump.py` is how you verify that assumption. It is also how you discover unfamiliar services that might be interesting targets but are not documented in any attack tool yet.

For a defender the same tool answers the question "what is my Windows server actually exposing?" Windows servers register dozens of RPC services at boot. Most administrators have never seen a complete list. Running `rpcdump.py` against your own servers is the fastest way to see what the attack surface really looks like.

By default `rpcdump.py` connects to TCP port 135, where the endpoint mapper will answer anonymous queries. No credentials are required. This is a feature of the Windows protocol itself, not an oversight. The endpoint mapper is designed to be a lookup service that any potential client can consult before authenticating to the actual service it wants.



## Why it exists

To understand why a dedicated endpoint mapper dumper tool exists, you have to understand the problem that MSRPC was built to solve in the 1990s and the design consequences of the solution.

Microsoft adopted the DCE/RPC specification from the Open Software Foundation in the early days of Windows NT. DCE/RPC is a general purpose remote procedure call framework originally designed for the Distributed Computing Environment, a late 1980s effort to make Unix workstations act as one giant distributed computer. When Microsoft brought it into Windows, they kept a specific design choice that has shaped Windows network security ever since: **most services do not listen on a fixed, predictable port.** Services pick a dynamic high port at boot time and then register their existence with a centralized directory service so that clients can find them. That directory service is the endpoint mapper.

From a software engineering perspective this is elegant. From a security perspective it means every Windows network has a locator service on port 135 that cheerfully tells anyone who asks what internal services are running and where to find them. Finding RPC services without the endpoint mapper would be a port scan over sixteen thousand ephemeral ports followed by protocol fingerprinting. Finding them with the endpoint mapper is one query.

`rpcdump.py` ships with Impacket because the project's authors needed a reliable way to ask the endpoint mapper for its full listing during research. The Samba project has a similar tool. So does Microsoft, in the form of `rpcdump.exe` from the Windows Resource Kit. The Impacket version runs from Linux, macOS, or anywhere Python runs, and it supports transports the other two do not, including RPC over HTTP for environments where 135 is firewalled but 443 is not.



## The protocol theory

This section is longer than you might expect for a simple enumeration tool. The reason is that almost every other MSRPC article in this wiki assumes you understand the concepts defined here. If you internalize DCE/RPC interfaces, UUIDs, and bindings now, the rest of the wiki will read much faster.

### DCE/RPC in one paragraph

DCE/RPC lets a client call a function on a remote server as if the function were local. The client invokes a Python call, C function, or wrapper method. That call is marshalled into a network message, sent to the server, executed by the server's matching function, and the return value is unmarshalled back to the client. From the client's perspective the remote call looks like a local one. From the network's perspective it looks like a series of structured RPC messages. Microsoft's implementation of this is what the Windows world calls MSRPC.

### Interfaces and UUIDs

Every RPC service is identified by a 128 bit number called a **UUID** (Universally Unique Identifier). Microsoft refers to these as interface identifiers. The UUID is not a friendly name, it is a fixed binary identifier that both the server and the client agree on ahead of time. When a client wants to call a function on a specific service, the first thing it does is negotiate a binding to that UUID. The server either supports that UUID or it refuses.

A few UUIDs you will see over and over in this wiki:

| Interface | UUID | What it speaks |
|:---|:---||
| SAMR | `12345778-1234-abcd-ef00-0123456789ac` | Security Account Manager (users, groups) |
| LSARPC | `12345778-1234-abcd-ef00-0123456789ab` | Local Security Authority (SIDs, policy) |
| SCMR | `367abb81-9844-35f1-ad32-98f038001003` | Service Control Manager |
| SRVSVC | `4b324fc8-1670-01d3-1278-5a47bf6ee188` | Server service |
| WKSSVC | `6bffd098-a112-3610-9833-46c3f87e345a` | Workstation service |
| DRSUAPI | `e3514235-4b06-11d1-ab04-00c04fc2dcd2` | Directory replication (DCSync lives here) |
| EPM itself | `e1af8308-5d1f-11c9-91a4-08002b14a0fa` | Endpoint mapper |
| TSCH | `86d35949-83c9-4044-b424-db363231fd0c` | Task Scheduler |
| RRP | `338cd001-2244-31f1-aaaa-900038001003` | Remote Registry |

The endpoint mapper itself has a UUID, the last row in the table above. The endpoint mapper is an RPC service that lets you look up other RPC services. It is turtles all the way down in the best possible way.

### String bindings

A **binding** describes how to reach a specific RPC interface on a specific machine. Bindings are written as string bindings for human consumption. The format is strict. You will see it throughout Impacket source and throughout the output of `rpcdump.py`.

```text
ncacn_ip_tcp:10.0.0.10[49152]
```

Read that as "Network Computing Architecture Connection oriented (ncacn), over IP TCP, to host 10.0.0.10, on port 49152." The pieces are:

- **Protocol sequence**. `ncacn_ip_tcp` for direct TCP, `ncacn_np` for named pipes over SMB, `ncacn_http` for HTTP, `ncalrpc` for local only interprocess calls.
- **Network address**. An IP address, hostname, or the placeholder used for local connections.
- **Endpoint**. The TCP port, the named pipe path, or the HTTP URL suffix, depending on the protocol sequence.

`rpcdump.py` has a short dictionary called `KNOWN_PROTOCOLS` that maps a destination port to a string binding template:

```python
KNOWN_PROTOCOLS = {
    135: {'bindstr': r'ncacn_ip_tcp:%s[135]'},
    139: {'bindstr': r'ncacn_np:%s[\pipe\epmapper]'},
    443: {'bindstr': r'ncacn_http:[593,RpcProxy=%s:443]'},
    445: {'bindstr': r'ncacn_np:%s[\pipe\epmapper]'},
    593: {'bindstr': r'ncacn_http:%s'}
}
```

Those are the five supported ways to reach an endpoint mapper. We will cover when to use each one later.

### Dynamic versus static endpoints

Some RPC services live on fixed, well known ports. The endpoint mapper itself is one of them: always port 135 on TCP, always port 593 for RPC over HTTP. A small number of other services also have fixed endpoints.

**Most services do not.** The Service Control Manager, the Task Scheduler, the Remote Registry, and dozens of others pick a random high port (typically in the 49152 to 65535 range) at boot time. They then register with the endpoint mapper, saying in effect: "I am UUID 367abb81-9844-35f1-ad32-98f038001003. I am listening on TCP port 49664. My friendly name is Microsoft Windows Service Control Manager."

When a client wants to talk to the Service Control Manager, the client does three things:

1. Connect to the endpoint mapper on port 135.
2. Call `ept_lookup` with the target UUID.
3. Receive the dynamic port number, then connect to that port.

Some tools skip step one entirely by using named pipes over SMB. Named pipe transports have a fixed path (for example `\pipe\svcctl` for the Service Control Manager), so you do not need a locator. This is why so many Impacket tools connect over port 445 rather than port 135. The SMB path provides both authentication and a fixed endpoint, and it tunnels through many firewalls that block port 135.

### The endpoint mapper interface

The endpoint mapper exposes a small number of RPC operations. The one `rpcdump.py` uses is `ept_lookup`. Calling `ept_lookup` with no filters returns every endpoint the server knows about. The response is a list of structures called **towers**. Each tower is a packed representation of a complete binding, including the interface UUID, the interface version, the protocol sequence, the network address, and the endpoint.

`rpcdump.py` walks the response, unpacks each tower, and prints it in a form humans can read. The `PrintStringBinding` function in `impacket.dcerpc.v5.epm` is the code that does the formatting. When you read the output, you are reading the unpacked contents of the towers the server returned.

### Why the endpoint mapper answers anonymous queries

Port 135 does not require authentication for `ept_lookup`. This is deliberate and dates back to DCE design principles. The endpoint mapper is a locator service. A client needs to know where a service is before it can authenticate to it. Forcing authentication on the locator would create a chicken and egg problem where you need credentials to find the service you need credentials to talk to.

In practice this means any host that can reach port 135 can enumerate every registered RPC service on the target, even from a fully unauthenticated position. From a defender's perspective this is why segmentation of port 135 matters. From an attacker's perspective this is why `rpcdump.py` is often the first command after a port scan confirms 135 is open.

### The ACL gotcha on ports 139 and 445

One historical quirk worth knowing. When you reach the endpoint mapper through its named pipe path (`\pipe\epmapper` on port 139 or 445), the pipe is protected by an ACL that requires an authenticated SMB session. The same endpoint mapper, the same query, the same answer, but the transport requires credentials. This is why `rpcdump.py` accepts `-hashes` and other authentication flags even though the default port 135 does not need them.



## How the tool works internally

The script is short and easy to read. Walk through it once with the source open in a tab and it will all make sense. The flow is:

1. **Argument parsing.** The `argparse` block reads the positional target, the `-port` choice, the optional `-target-ip`, and the authentication flags.

2. **Target parsing.** The standard Impacket `parse_target` utility splits the positional string into domain, username, password, and target host. For ports 135 and 593 these fields stay empty because the tool does not need them.

3. **Protocol selection.** Based on the chosen `-port`, the tool picks one of the five string binding templates from the `KNOWN_PROTOCOLS` dictionary shown earlier. The template gets filled in with the target host, producing a concrete string binding like `ncacn_ip_tcp:10.0.0.10[135]`.

4. **Transport creation.** `impacket.dcerpc.v5.transport.DCERPCTransportFactory` is called with the string binding. The factory returns an appropriate transport object: a `TCPTransport` for `ncacn_ip_tcp`, an `SMBTransport` for `ncacn_np`, or an `HTTPTransport` for `ncacn_http`. This factory pattern is the same one used by every other MSRPC tool in Impacket.

5. **Authentication, if needed.** For named pipe and HTTP transports, the tool sets credentials on the transport object. For direct TCP on 135 or 593, nothing happens here.

6. **Connect and bind.** The transport's `connect()` method opens the socket or pipe. A DCERPC bind request negotiates the endpoint mapper interface UUID.

7. **`ept_lookup`.** The tool calls `hept_lookup` from `impacket.dcerpc.v5.epm`. This is a helper that wraps the `ept_lookup` opnum with sensible defaults. The call returns an iterable of tower entries.

8. **Formatting.** The tool groups the entries by UUID and prints each group. For every entry it calls `PrintStringBinding` to produce the human readable binding. It also looks up the UUID in a built in table of known interface names, so that `12345778-1234-abcd-ef00-0123456789ac` prints as `MS NT Directory Services`.

The entire logic of the tool, excluding argument parsing and error handling, is about fifty lines of Python. Reading it in parallel with this article is the fastest way to solidify the concepts.



## Authentication options

The behavior depends entirely on which port you are talking to.

### Port 135 (TCP): no authentication

```bash
rpcdump.py 10.0.0.10
```

No credentials. Works against any host that exposes port 135 to the network. This is the default.

### Port 593 (TCP): no authentication

```bash
rpcdump.py -port 593 10.0.0.10
```

Same semantics as port 135, but over RPC over HTTP's dedicated TCP port. Rarely exposed directly. More commonly used as the backend behind an RPC Proxy on port 443.

### Port 445 (SMB): NTLM required

```bash
rpcdump.py -port 445 CORP/alice:'S3cret!'@dc01.corp.local
```

The tool tunnels RPC over an SMB session to the named pipe `\pipe\epmapper`. The SMB session itself requires authentication, so credentials are mandatory. Useful when port 135 is blocked but port 445 is not.

### Port 139 (NetBIOS): NTLM required

```bash
rpcdump.py -port 139 CORP/alice:'S3cret!'@10.0.0.10
```

Legacy NetBIOS over TCP path. Same named pipe, same credential requirement, different transport port. Mostly encountered on older environments.

### Port 443 (RPC Proxy over HTTPS): NTLM required

```bash
rpcdump.py -port 443 -hashes :<nthash> CORP/alice@outlook.corp.local
```

This mode treats the target as an RPC Proxy server, like the front end of a historical Outlook Anywhere deployment. The Proxy accepts HTTP requests with an `RPC_IN_DATA` and `RPC_OUT_DATA` channel pair, authenticates using NTLM over HTTP, and tunnels the RPC to a backend server reachable on port 593. Useful for enumerating services on an internal Exchange or RPC capable backend when the only path in is HTTPS on 443.

### Pass the hash variants

The `-hashes` flag accepts the `LMHASH:NTHASH` format and works for any of the three authenticated ports above. The usual pattern applies: blank LM hash before the colon for anything Vista or newer.

```bash
rpcdump.py -port 445 -hashes :aad3b435b51404eeaad3b435b51404ee8846f7eaee8fb117ad06bdd830b7586c CORP/alice@dc01
```

`rpcdump.py` does not support the `-k` Kerberos flag directly. In practice this rarely matters, because the most common use of the tool is against port 135 with no authentication at all.



## Practical usage

### Basic enumeration

```text
$ rpcdump.py 10.0.0.10
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

Protocol: [MS-RPRN]: Print System Remote Protocol
Provider: spoolsv.exe
UUID    : 12345678-1234-ABCD-EF00-0123456789AB v1.0
Bindings:
    ncacn_ip_tcp:10.0.0.10[49664]
    ncacn_np:10.0.0.10[\PIPE\spoolss]

Protocol: [MS-DCOM]: Distributed Component Object Model Remote Protocol
Provider: N/A
UUID    : 000001A0-0000-0000-C000-000000000046 v0.0
Bindings:
    ncacn_ip_tcp:10.0.0.10[49668]

Protocol: [MS-SCMR]: Service Control Manager Remote Protocol
Provider: services.exe
UUID    : 367ABB81-9844-35F1-AD32-98F038001003 v2.0
Bindings:
    ncacn_np:10.0.0.10[\PIPE\svcctl]

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol
Provider: schedsvc.dll
UUID    : 86D35949-83C9-4044-B424-DB363231FD0C v1.0
Bindings:
    ncacn_ip_tcp:10.0.0.10[49665]

...
```

A real output from a Windows domain controller will run to 60 or more entries, sometimes well over 100. Each entry corresponds to an RPC interface the host is willing to serve. The `Protocol` line usually carries the Microsoft specification identifier for the interface, which is a direct link to the public documentation for that protocol.

### Reading an entry

Consider this one:

```text
Protocol: [MS-SCMR]: Service Control Manager Remote Protocol
Provider: services.exe
UUID    : 367ABB81-9844-35F1-AD32-98F038001003 v2.0
Bindings:
    ncacn_np:10.0.0.10[\PIPE\svcctl]
```

The five pieces of information this tells you:

- **`[MS-SCMR]`** is the specification. You can go read `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/` and learn every call this interface supports.
- **`services.exe`** is the process that registered the endpoint. Useful for forensic correlation and for pivoting to process based detections.
- **`367ABB81-9844-35F1-AD32-98F038001003`** is the UUID. This is what `psexec.py`, `services.py`, and `secretsdump.py` all use when they talk to the Service Control Manager.
- **`v2.0`** is the interface version.
- **`ncacn_np:10.0.0.10[\PIPE\svcctl]`** is the binding. To reach this service, open the SMB named pipe `\pipe\svcctl` on 10.0.0.10. Because this is a named pipe, you will need an SMB session, which means authentication.

### Enumerating through port 445 when 135 is blocked

Many environments filter port 135 at the perimeter. Port 445 is usually left open because file sharing and Active Directory need it. Switch transports:

```bash
rpcdump.py -port 445 CORP/alice:'S3cret!'@fs01.corp.local
```

Same output, same information, different transport under the hood. The only trade off is that you need valid credentials for SMB.

### Enumerating through RPC Proxy on 443

For environments where only HTTPS is reachable:

```bash
rpcdump.py -port 443 CORP/alice:'S3cret!'@outlook.corp.local
```

This used to matter more in the Exchange Outlook Anywhere era. It still matters in some environments with legacy RPC proxy deployments, and it is a good pattern to know for reviewing any web service that advertises RPC tunneling.

### Chasing a specific service

If you want to know whether a host exposes the Print Spooler (relevant for PrintNightmare and PetitPotam research) pipe the output into grep:

```bash
rpcdump.py dc01.corp.local | grep -i print
```

Or for DCSync readiness:

```bash
rpcdump.py dc01.corp.local | grep -iE 'DRSR|replication'
```

### Looping across a subnet

`rpcdump.py` does not have a built in range scanner. A shell loop does the job:

```bash
for ip in $(seq 1 254); do
  timeout 5 rpcdump.py 10.0.0.${ip} 2>/dev/null | grep -q 'Protocol:' && \
    echo "10.0.0.${ip} has EPM open"
done
```

This identifies every host on the `/24` with a responsive endpoint mapper. Combine with `-port 445` if you want to cover Windows servers where 135 is filtered but 445 is open.



## What it looks like on the wire

A packet capture of a default `rpcdump.py` invocation against port 135 is short and clean.

1. **TCP handshake on port 135.** Standard three way SYN, SYN ACK, ACK.

2. **DCE/RPC Bind request.** The client sends a Bind PDU naming the endpoint mapper interface UUID (`e1af8308-5d1f-11c9-91a4-08002b14a0fa`), version 3.0. This is the first RPC level message of the session. Wireshark's display filter `dcerpc` will show it.

3. **DCE/RPC Bind Ack response.** The server accepts the bind and acknowledges the transfer syntax.

4. **DCE/RPC Request: `ept_lookup`.** The client issues the actual query. The request carries optional filters (all left empty for a full dump) and a handle indicating the starting point for pagination.

5. **DCE/RPC Response.** The server returns a batch of tower entries. If the list is long enough, the tool will make additional `ept_lookup` calls using the opaque entry handle returned by the server. Each call returns the next batch until the handle comes back as empty, which signals the end of the enumeration.

6. **TCP FIN / FIN ACK.** The client closes the connection.

In Wireshark with the `dcerpc` display filter and decoding enabled, you can see every UUID returned by the server in the Packet Details pane. This is a useful exercise: pick one of those UUIDs, switch to the `dcerpc` Decode As menu, and Wireshark will show the traffic for that specific service if it is present in the capture.

When `rpcdump.py` is invoked against port 445, the packet sequence is longer because of the SMB setup preamble:

1. TCP handshake on port 445.
2. SMB2 Negotiate.
3. SMB2 Session Setup (authentication).
4. SMB2 Tree Connect to `\\target\IPC$`.
5. SMB2 Create for `\pipe\epmapper`.
6. DCE/RPC Bind, Request, Response as above, tunneled over SMB2 Write and Read.
7. SMB2 Close, Tree Disconnect, Logoff.
8. TCP FIN.

Recognizing this pattern is worthwhile. It is the exact pattern every RPC over SMB tool in Impacket follows. Once you can read it fluently, every remote execution tool, every credential dumping tool, and every AD modification tool reads like minor variations on this theme.



## What it looks like in logs

`rpcdump.py` is noisy enough to be detectable if logging is configured, but default Windows installations do not log much about endpoint mapper activity. The artifacts depend heavily on which port and which operating system version.

### Port 135 (TCP, anonymous)

- **Windows Firewall log.** If Windows Firewall is in logging mode, an inbound TCP connection to port 135 will appear. On most production servers this log is off by default.
- **Security log.** Nothing. The anonymous EPM query does not trigger a logon event.
- **Sysmon Event ID 3 (Network connection).** Logs the inbound TCP connection if Sysmon is installed and configured to cover port 135. This is usually the richest native signal available.
- **Sysmon Event ID 22 (DNS query).** On the attacker side, may capture the name resolution for the target.
- **RPC Client Access Log on Exchange.** Exchange servers have been known to log `ept_lookup` calls in internal RPC client access logs, because Exchange handles RPC intensively and its logging is more aggressive than a default server.

### Ports 139 and 445 (SMB tunneled)

- **Security Event ID 4624 (Logon).** An authenticated SMB session fires a network logon. Logon Type 3. The `IpAddress` field gives you the source.
- **Security Event ID 4672** (Special privileges) if an administrator authenticated.
- **Security Event ID 5140 (Share accessed).** Logs the `IPC$` tree connect if detailed file share auditing is on.
- **Security Event ID 5145 (Detailed file share).** If enabled, logs the access attempt against the `epmapper` pipe. This is the most specific signal available, but it requires "Audit Detailed File Share" to be configured.
- **Security Event ID 4634 (Logoff).** At the end of the session.

### Port 443 (RPC Proxy)

- **IIS access logs** on the RPC Proxy server. Will show the `RPC_IN_DATA` and `RPC_OUT_DATA` HTTP verbs with the authenticated user.
- **Security logs** follow whatever IIS is configured to do.

### Sysmon content that helps the most

A Sysmon config that captures Event ID 3 for inbound connections on ports 135, 139, 445, and 593 plus Event ID 18 for named pipe activity on `\pipe\epmapper` gives a complete picture. Florian Roth's and Olaf Hartong's public Sysmon configs include versions of this rule.



## Detection and defense

### Detection opportunities

Enumeration traffic is legitimate. Domain controllers, Exchange servers, and management tools legitimately query the endpoint mapper as part of normal operations. The detection problem is separating those legitimate queries from reconnaissance.

**Unusual source hosts.** A workstation that has never before connected to port 135 on the domain controllers suddenly doing so is suspicious. Build baselines of which hosts normally talk to which ports, then alert on outliers.

**Broad scanning behavior.** One host hitting port 135 on many targets in a short window, or one target receiving port 135 connections from many sources in a short window, both stand out. Threshold based detections on Sysmon Event ID 3 or firewall logs catch this well.

**Paired EPM lookup and dynamic port connection.** A sophisticated detection is the sequence: the same source connects to port 135, then within seconds connects to a high port on the same target. That is the exact footprint of `rpcdump.py` followed by a follow on RPC tool. Correlation rules in a SIEM can catch this pattern.

**Unauthenticated SMB named pipe access to `\pipe\epmapper`.** Very rare from legitimate workflows. Most legitimate EPM lookups use TCP 135 directly. An inbound named pipe open for `\pipe\epmapper` from an unusual source is a strong signal.

A starter Sigma style rule focused on that last pattern:

```yaml
title: Endpoint Mapper Named Pipe Access
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5145
    RelativeTargetName|contains: '\epmapper'
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
level: medium
```

The filter excludes computer accounts, which legitimately probe EPM during normal domain operations. Expect to tune this against your environment.

### Preventive controls

Most of the hardening that matters for `rpcdump.py` is network segmentation, not host level controls.

- **Block TCP 135 and 593 at the perimeter.** These ports have no legitimate reason to be reachable from the internet. If they are, the attack surface extends well beyond endpoint mapper enumeration; every RPC service becomes a candidate target.
- **Segment TCP 135 internally.** A finance workstation does not need to reach the Service Control Manager or the Directory Replication interface on the domain controllers. Network segmentation between user subnets and server subnets closes most of the practical attack surface.
- **Require SMB signing on servers.** SMB signing does not prevent port 445 based EPM enumeration once an attacker has credentials, but it prevents NTLM relay attacks that would otherwise let an attacker chain EPM information into code execution.
- **Disable RPC over HTTP where not needed.** The RPC Proxy role was designed for legacy Outlook Anywhere deployments. Most modern Exchange and line of business applications have better alternatives. If you are not actively using RPC over HTTP, uninstall it.
- **Restrict named pipe access anonymously.** The `RestrictNullSessAccess` and `NullSessionPipes` registry values control which pipes are accessible to unauthenticated sessions. Modern Windows defaults are good, but older installations and hardened inherited configurations need to be verified.
- **Audit detailed file share.** Turn on "Audit Detailed File Share" on your servers so that Event ID 5145 records access to `\pipe\epmapper` and any other named pipe. The volume is manageable with filtering.

None of these controls prevent `rpcdump.py` from working when the attacker is on the same network as the target. That is by design of the protocol. The controls reduce the distance from which enumeration is possible and increase the visibility when it happens.



## Related tools and attack chains

`rpcdump.py` is step one. Every tool in this wiki that uses MSRPC assumes the target service is reachable, and this is how you confirm it.

- **[`rpcmap.py`](rpcmap.md).** The natural follow up. Where `rpcdump.py` lists registered endpoints, `rpcmap.py` actively probes a specific endpoint to learn which operations it supports. The two together give a complete picture of an RPC surface.
- **[`samrdump.py`](samrdump.md).** Uses the SAMR UUID that `rpcdump.py` can reveal is listening. Often the next step once you confirm SAMR is exposed.
- **[`services.py`](../08_remote_system_interaction/services.md) and [`reg.py`](../08_remote_system_interaction/reg.md).** Both use interfaces whose bindings `rpcdump.py` reveals.
- **[`secretsdump.py`](../03_credential_access/secretsdump.md).** Relies on DRSUAPI (for DCSync) and several other interfaces. Running `rpcdump.py` against a domain controller first is a good sanity check that the necessary services are exposed.
- **[`psexec.py`](../04_remote_execution/psexec.md), [`smbexec.py`](../04_remote_execution/smbexec.md), [`atexec.py`](../04_remote_execution/atexec.md).** All three speak RPC over SMB to services that `rpcdump.py` can reveal.
- **[`smbclient.py`](../05_smb_tools/smbclient.md).** The companion tool. `smbclient.py` gets you inside the SMB layer, `rpcdump.py` gets you a directory of the RPC layer on top. Reading both back to back is the clearest way to internalize how Windows remote administration is layered.

A common reconnaissance sequence looks like this.

1. **Port scan.** Identify hosts with 135, 139, 445, or 593 open.
2. **`rpcdump.py`.** For each responding host, list the RPC services available.
3. **Target selection.** Pick the UUIDs that map to services you care about (DRSUAPI on domain controllers for DCSync, SCMR on any server for remote service manipulation, Task Scheduler for persistence, and so on).
4. **Authenticated follow up.** Use the appropriate Impacket tool to interact with the selected service, usually with credentials obtained from `GetUserSPNs.py`, `GetNPUsers.py`, or a hash captured earlier.



## Further reading

- **`[MS-RPCE]`: Remote Procedure Call Protocol Extensions.** The Microsoft specification that defines DCE/RPC as implemented by Windows. Start at `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/`. Section 2.2 covers the PDU formats and is the best grounding for reading an RPC packet capture.
- **`[MS-RPCH]`: RPC over HTTP Protocol Specification.** Covers the RPC Proxy mode used by port 443.
- **Open Group C706: DCE 1.1 Remote Procedure Call.** The upstream specification that MSRPC extends. The sections on interface definition, UUIDs, and string bindings are the authoritative reference.
- **`impacket/dcerpc/v5/epm.py`.** The module in the Impacket library that implements the endpoint mapper client. Worth reading alongside this article. The `hept_lookup` function and the `PrintStringBinding` helper are each short and educational.
- **MITRE ATT&CK T1046 Network Service Discovery** at `https://attack.mitre.org/techniques/T1046/`.
- **SpecterOps blog, "A Guide to Attacking Domain Trusts" and related posts.** Discuss how `rpcdump.py` fits into real world offensive workflows.
- **Microsoft's list of well known RPC interface UUIDs.** Search Microsoft Learn for the UUID of any interface in the output to land on the relevant `[MS-XXXX]` specification.
- **Sysmon configuration repositories by Florian Roth (Neo23x0) and Olaf Hartong.** Both include EPM aware detection rules that can be adapted to your environment.

Run `rpcdump.py` against a lab domain controller once. Read the output line by line. Look up three UUIDs you do not recognize. This is the single best way to turn the theory in this article into working knowledge that will pay dividends for every other article in the wiki.
