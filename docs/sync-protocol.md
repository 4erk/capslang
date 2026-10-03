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

## Reconnection contract (broker not implemented yet)

Do not replay an old session's counters after restart/reconnection. Before
constructing a new replica, the broker must reconcile actual recipient activity,
exchange a fresh random session ID, confirm both peers, and agree on the initial
language. Old-session packets are rejected, not promoted to current events.

Compare monotonic activity ages measured at the same instant, never absolute
clocks from two devices. A remote age reported at reply-send time has interval
`[age, age + measured RTT]` at receipt. The helper selects a winner only when the
intervals are separated by more than 100 ms. Missing, malformed, or overlapping
ages return AwaitInput. A coordinator still has to reject stale measurements,
confirm the proposal and handle fresh input racing that proposal; this helper
does not implement that negotiation. After ambiguity, fresh *delivered* input
must decide the language, not an arbitrary preference for the PC.

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
