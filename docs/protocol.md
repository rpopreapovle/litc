# LiTC P2P Wire Protocol (added after RPC)

The peer-to-peer protocol is deliberately tiny and **binary only** — no JSON on
the wire. It reuses the same `litc-wire` codec as the node's local RPC
(see [rpc.md](rpc.md) and [roadmap.md](roadmap.md)). One format, everywhere.

## Framing

```
| magic: 4 bytes | cmd: 1 byte | len: 4 bytes (u32 BE) | payload: len bytes |
```

- `magic`: network magic (testnet/mainnet differ), e.g. `0xL1TC`.
- `cmd`: one of the message types below.
- `len`: length of `payload`.
- `payload`: fixed/var binary layout per command (no text, no JSON).

## Messages (twelve; 1–10 are P2P, 11–12 are local RPC)

| cmd | Name     | payload (binary)                              | purpose |
|-----|----------|-----------------------------------------------|---------|
| 1   | version  | ver, services, timestamp, nonce, best_height  | handshake init |
| 2   | verack   | —                                             | handshake ack |
| 3   | inv      | count + (type, hash)…                         | announce tx/blocks |
| 4   | getdata  | count + (type, hash)…                         | request tx/blocks |
| 5   | tx       | raw transaction bytes                         | full transaction |
| 6   | block    | raw block bytes                               | full block |
| 7   | ping     | nonce                                         | keepalive / latency |
| 8   | pong     | nonce                                         | reply to ping |
| 9   | getaddr  | —                                             | ask for peer addresses |
| 10  | addr     | count + (NetAddr{services,ip:16,port:u16,timestamp}) | peer addresses |
| 11  | request  | id, method, params                            | RPC call (local) |
| 12  | response | id, ok, data                                 | RPC result (local) |

That is the entire protocol. No address managers beyond `getaddr`/`addr`, no
extra gossip, no negotiated extensions — per [PHILOSOPHY.md](../PHILOSOPHY.md),
nothing that does not simplify or help the ordinary user. At 15 s / 750 KB blocks,
relay should use **compact blocks** (announce a block by short tx IDs; fetch the
few missing txs) so propagation stays fast — full `block` is the fallback.

That is the entire protocol. No address managers, no extra gossip, no
negotiated extensions — per [PHILOSOPHY.md](../PHILOSOPHY.md), nothing that
does not simplify or help the ordinary user.

## Flow

1. A connects to B → sends `version`.
2. B replies `verack` then its own `version`; A replies `verack`.
3. Peers exchange `inv` (hashes); missing items requested via `getdata`;
   answered with `tx`/`block`.
4. `ping`/`pong` keep the connection alive.

## Notes

- Serialization on the wire reuses `litc-wire` (the single codec for node RPC
  and P2P alike); there is no second format.
- Difficulty, validation, and reorg rules are unchanged from
  [specification.md](specification.md) — P2P only moves data.
