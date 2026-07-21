# LiTC URI Scheme

Standard payment URIs for LiTC, modelled after BIP-21 (`bitcoin:`). Designed
for QR codes, deep links, copy-paste, and wallet interop.

## Scheme name

```
litc:
```

No separate testnet scheme — the network is encoded **inside** the address
(`L…`/`m…` for WOTS+, `litc…`/`tlitc…` for stealth). Wallets detect the
network from the address prefix.

## Syntax

```
litc:<address>[?amount=<satoshis>][&label=<text>][&message=<text>]
```

| Component | Required | Description |
|-----------|----------|-------------|
| `address` | yes | A LiTC address (stealth or WOTS+) |
| `amount`  | no  | Amount in **satoshis** (integer, no decimals) |
| `label`   | no  | Short label for the recipient (UTF-8, URL-encoded) |
| `message` | no  | Payment note / memo (UTF-8, URL-encoded) |

Parameters are separated by `&`. The first parameter uses `?`.

### Reserved parameters (future)

| Parameter | Description |
|-----------|-------------|
| `r`       | BIP-70-style payment request URL (HTTPS) |
| `time`    | Payment request expiry (unix timestamp) |
| `expire`  | Seconds until the request expires |
| `chain`   | Explicit network hint (`mainnet` / `testnet`) — normally inferred |

## Address formats

### Stealth address (recommended)

Reusable, post-quantum. **This is the address users should share.**

```
Bech32m(KEM_version || KEM_pk)
```

- Mainnet: HRP `litc`, version `0x31`
- Testnet: HRP `tlitc`, version `0x70`
- Length: ~1300 characters (800-byte KEM key)

```
litc:litc1qqqq...<bech32m data>...qqxq9cxsy?amount=1000000&label=Alice
```

### WOTS+ one-time address (legacy)

One-time, derived per payment. For compatibility only; prefer stealth.

```
base58check(version || HASH160(R))
```

- Mainnet: version `0x30` → addresses start with `L`
- Testnet: version `0x6F` → addresses start with `m`

```
litc:LXhE3gHJzVtGHbPQ...<base58>...<checksum>?amount=50000
```

## QR code encoding

The QR code content is the **raw URI string**:

```
litc:<address>[?params...]
```

### QR parameters

| Property | Value |
|----------|-------|
| Format   | UTF-8 text |
| Error correction | **M** (15%) minimum; **L** acceptable for short URIs |
| Max payload | QR Version 40, binary: 2,953 bytes — stealth URIs (~1350 chars) fit comfortably |

### QR generation workflow

1. Build the URI string.
2. Encode as UTF-8 bytes.
3. Generate QR with error correction level M.
4. (Optional) Overlay logo in center — keep below 30% of QR area.

### Size guidelines

| Use case | QR modules | Physical size |
|----------|-----------|---------------|
| Screen display | 25×25+ | ≥ 2 cm × 2 cm |
| Print (paper) | 33×33+ | ≥ 2.5 cm × 2.5 cm |
| Small sticker | 21×21 | ≥ 1.5 cm × 1.5 cm |

## Examples

### Basic payment request

```
litc:litc1qq...?amount=1000000
```

Encoded in QR:
```
┌─────────────────────┐
│  ██ ▄▄▄ █▄█ ▄▄▄ █  │
│  █▄█ █▄█ █▄█ █▄█ █  │
│  ██ ▄▄▄ █▀█ ▄▄▄ ██ │
│  ...                │
│  litc:litc1qq...    │
└─────────────────────┘
```

### Payment with label and memo

```
litc:litc1qq...?amount=500000&label=Coffee%20Shop&message=Order%20%2342
```

### WOTS+ address (legacy)

```
litc:LXhE3gHJzVtGHbPQKj7nR9mW4sT1yU6iO0p?amount=25000
```

### Testnet

```
litc:tlitc1qq...?amount=100000
```

## Parsing rules

1. **Validate prefix**: string must start with `litc:` (case-insensitive).
2. **Extract address**: everything before `?` (or the full string if no `?`).
3. **Detect address type**:
   - Starts with `litc1` or `tlitc1` → **stealth** (Bech32m)
   - Starts with `L` or `m` → **WOTS+** (base58check)
4. **Parse query parameters**: standard `key=value` pairs, URL-decoded.
5. **Validate amount**: if present, must be a positive integer (satoshis).
6. **Unknown parameters**: ignored (forward-compatible).

## Error handling

| Condition | Behavior |
|-----------|----------|
| Invalid prefix (not `litc:`) | Reject |
| Empty address | Reject |
| Unknown address prefix | Reject |
| Amount ≤ 0 or non-integer | Reject |
| Unknown query params | Ignore |
| URL encoding errors | Reject |

## Wallet CLI integration

### Display QR

```bash
litc wallet receive            # prints QR to terminal (ASCII art)
litc wallet receive --svg      # prints SVG to stdout
litc wallet receive --png out.png  # saves PNG file
litc wallet receive --amount 1000000  # pre-filled amount
```

### Parse URI (from clipboard, QR scan, deep link)

```bash
litc wallet decode-uri "litc:litc1qq...?amount=100000"
# → address: litc1qq...
# → amount: 100000
# → type: stealth
# → network: mainnet
```

### Send from URI

```bash
litc wallet send-uri "litc:litc1qq...?amount=100000"
# equivalent to: litc wallet send-stealth litc1qq... 100000
```

## Comparison with BIP-21

| Aspect | BIP-21 (Bitcoin) | LiTC URI |
|--------|-------------------|----------|
| Scheme | `bitcoin:` | `litc:` |
| Amount unit | BTC (decimal) | satoshis (integer) |
| Address types | P2PKH, P2SH, bech32 | WOTS+ (base58), stealth (bech32m) |
| Network encoding | In address prefix | In address prefix |
| Payment requests | `r=` parameter | `r=` parameter (reserved) |
| QR content | URI string | URI string |

## Security notes

- **Amount in satoshis, not LIT.** Avoids floating-point ambiguity.
- **Label and message are informational.** They are NOT signed or on-chain.
- **Stealth addresses are long (~1300 chars).** QR codes handle this fine
  (Version 40 supports 2953 bytes), but wallets should also support
  truncation + server-side resolution for UX.
- **No `r=` in QR by default.** Payment requests (BIP-70 style) require HTTPS
  and are a separate flow. QR should encode the address directly.
