# Development protocol — not LAN release acceptance

`core/sync.hpp` is a deterministic, Windows-independent state machine.
`network/language_channel.hpp` transports its frames using paired Schannel TLS.
Neither file implements pairing, LAN discovery, MWB recipient detection, or
application installation. Do not wire an unconfirmed MWB candidate into it.

## Wire v1

Exactly 64 bytes, unsigned multi-byte fields in network (big-endian) order:

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 4 | ASCII CLSP |
| 4 | 1 | Protocol version 1 |
| 5 | 1 | Update=1, Ack=2 |
| 6 | 2 | Reserved, zero |
| 8 | 16 | Negotiated connection session identifier |
| 24 | 16 | Event author identifier |
| 40 | 8 | Logical event counter, nonzero, below UINT64_MAX |
| 48 | 2 | EN=0409, RU=0419 |
| 50 | 1 | Update: zero; Ack: Pending=1, Applied=2, Failed=3, Locked=4 |
| 51 | 13 | Reserved, zero |

No native HKL, text, keyboard codes, cursor position, window titles, paths,
commands or system-clock timestamps are present. The parser rejects unknown
versions, flags, languages, sizes and zero identities. TLS authenticates the
peer; the broker must bind author identifiers to the pinned pair.

The stream adapter accepts fragmented and coalesced TLS records. It buffers at
most 1087 bytes and gives each complete-frame receive a 1500 ms deadline,
including all fragments. Invalid input permanently fails that adapter; the
owning broker must close the socket. No automatic fallback to plaintext.
The invitation listener cannot use the language adapter before a new fully
pinned connection is established.

## Ordering versus actual application

Inside one confirmed session, events use `(counter, author)` ordering. Local
changes increment the observed maximum counter. Duplicate, older and echoed
events do not toggle. Both peers break a simultaneous-event tie the same way;
transport listener/client roles do not influence this choice.

The target state is not proof of Windows application. The receiver sends a
separate acknowledgement tied to the exact event. Applied requires observing
the requested actual language; failure and lock remain explicit. A stale ack
cannot acknowledge a newer request. Focus changes and own applications must
not call `Replica::Local` as new user changes.

## Reconnection contract

Do not replay an old session's counters after restart/reconnection. Before
constructing a new replica, the broker must reconcile actual recipient activity,
exchange a fresh random session ID, confirm both peers, and agree on the initial
language. Old-session packets are rejected, not promoted to current events.

Compare monotonic activity ages measured at the same instant, never absolute
clocks from two devices. A remote age reported at reply-send time has interval
`[age, age + measured RTT]` at receipt. The helper selects a winner only when the
intervals are separated by more than 100 ms. Missing, malformed, or overlapping
ages return AwaitInput. A coordinator still has to reject stale measurements,
confirm the proposal and handle fresh input racing that proposal. The helper
alone does not implement that negotiation; `network/session.cpp` now does.
After ambiguity, fresh *delivered* input
must decide the language, not an arbitrary preference for the PC.

## Broker control v1 (development)

`core/session_wire.hpp` wraps negotiation and ordered polling in canonical
256-byte CLBP frames. Header: magic/version/kind/flags/reserved (8 bytes), random
connection ID (16), monotonically increasing round (8). Two 48-byte snapshot
slots contain engine incarnation, local intent revision, activity serial,
monotonic age bounds, EN/RU, activity-known and MWB-enabled booleans. An Offer
uses the second snapshot and an authority/target field. Poll/PollReply instead
carry zero or one CLSP Update and zero or one CLSP Ack in the final 128 bytes.
All unused bytes must be zero; decoding is checked by canonical re-encoding.

The listener coordinates Hello/Sample/Offer/Accepted/Commit/Committed, but its
language has no priority. Each side rechecks its own revision/engine before
commit. Ambiguous histories exchange fresh samples without applying anything.
The agreed version is seeded on both ends with the same author; this allows
actual initial application acknowledgements without inventing a user event.
After agreement, a 100 ms request/reply loop transports the newest local intent
and application status. There is one writer per TLS stream. Pending after an
earlier Applied is allowed: focus/unlock can require reapplying the same target.
Old-version/session acknowledgements cannot confirm newer work.

`runtime/engine_client` validates the local engine path, SID/session and required
elevation. Only SetLayoutIfRevision is used for peer updates. Queue success is
not Applied: `core/broker` requires matching target, actual language and worker
Applied status. Engine restart, MWB shutdown and disconnect invalidate the
session. The network worker never shares the keyboard callback thread.

Recipient activity remains an explicit dependency, **not** inferred from any
injected mouse event or `hDevice != nullptr`. The production recipient observer,
UI, installer and two-machine physical acceptance are still incomplete.

## Pairing and LAN transport (development)

`network/pairing` and `network/enrollment` implement a five-minute, single-use
128-bit invitation, user confirmation bound to the exact TLS peer certificate,
strict CLEP messages, and DPAPI pair records. The unpinned invitation connection
cannot carry language state. After confirmation, reconnect using mutual pins.
A lost final pairing acknowledgement is repaired by mutual-pin Resume rather
than rolling back an already-approved peer or accepting a different one.
Invitation strings/proofs must never be logged or put in diagnostic exports.

`network/lan` uses cancellable asynchronous DNS, bounded socket operations and
exclusive binding. Both directions reject peers outside physical Ethernet/Wi-Fi
on-link prefixes. The connector additionally checks the system's selected route;
it does not override a VPN route. This is additional enforcement, not a substitute
for the eventual narrowly scoped installer firewall rule. Local tests do not
install such a rule. API references: [GetAdaptersAddresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses)
and [Microsoft asynchronous resolver example](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/DNSAsyncNetworkNameResolution/cpp/ResolveName.cpp).

## Local certificate persistence

The identity blob contains certificate DER and the reference to a nonexported
user CNG key. It is protected with user-scoped DPAPI and a protected DACL granting
only current user/SYSTEM. DPAPI is defense against other accounts and offline
data inspection, not against malicious code already running as this user.
See [Microsoft DPAPI guidance](https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-using-cryptprotectdata).

Successful save transfers key lifetime from the temporary Identity object to
persistent storage. Failed loading only closes borrowed handles. Explicit erase
deletes the key, invalidates the certificate and removes the blob, permitting a
file-removal retry. The future installer/broker must own the single-instance
lock and crash-recovery policy; persistence here is not a migration transaction.

## Verification scope

Unit tests exercise duplicate/reordered/rapid/simultaneous events, acknowledgement
truthfulness, strict parsing and activity ambiguity. Windows tests additionally
reopen the certificate in a fresh process, reject corruption and mismatched
keys, check the real file DACL, and exchange language frames over actual TLS
with deliberately split/coalesced records. Layout application in those TLS
tests is a model, not a real desktop. Two-PC MWB acceptance remains required.
