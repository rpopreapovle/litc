# LiTC URI Scheme

Standard payment URIs for LiTC, modelled after BIP-21 (`bitcoin:`). Designed
for QR codes, deep links, copy-paste, and wallet interop.

## Scheme name

```
litc:
```

No separate testnet scheme — the network is encoded **inside** the address
(`litc1…` mainnet, `tlitc1…` testnet). Wallets detect the network from the
address prefix.

## Syntax

```
litc:<address>[?amount=<satoshis>][&label=<text>][&message=<text>]
```

| Component | Required | Description |
|-----------|----------|-------------|
| `address` | yes | A LiTC ML-DSA-2 address (`litc1q…` or `tlitc1q…`) |
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

## Address format

ML-DSA-2 (Dilithium, FIPS 204) addresses — ~40 characters.

```
bech32m("litc", version || HASH160(ml_dsa_pk))
```

- Mainnet: HRP `litc`, version `0x31` → `litc1q…`
- Testnet: HRP `tlitc`, version `0x70` → `tlitc1q…`
- Payload: `HASH160(ml_dsa_pk)` = 20 bytes
- Full public key (1312 bytes) is revealed at spend time in the witness

```
litc:litc1qvr83j4q2y9dxhlw4gkxp0n0a3q0n2m8m3z4c5x?amount=1000000&label=Alice
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
| Max payload | QR Version 40, binary: 2,953 bytes — litc URIs (~80 chars) fit easily |

### Size guidelines

| Use case | QR modules | Physical size |
|----------|-----------|---------------|
| Screen display | 21×21+ | ≥ 1.5 cm × 1.5 cm |
| Print (paper) | 25×25+ | ≥ 2 cm × 2 cm |

## Examples

### Basic payment request

```
litc:litc1qvr83j4q2y9dxhlw4gkxp0n0a3q0n2m8m3z4c5x?amount=1000000
```

### Payment with label and memo

```
litc:litc1qvr83j4q2y9dxhlw4gkxp0n0a3q0n2m8m3z4c5x?amount=500000&label=Coffee%20Shop&message=Order%20%2342
```

### Testnet

```
litc:tlitc1qvr83j4q2y9dxhlw4gkxp0n0a3q0n2m8m3z4c5x?amount=100000
```

## Parsing rules

1. **Validate prefix**: string must start with `litc:` (case-insensitive).
2. **Extract address**: everything before `?` (or the full string if no `?`).
3. **Detect network**:
   - Starts with `litc1` → **mainnet**
   - Starts with `tlitc1` → **testnet**
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
litc wallet decode-uri "litc:litc1q...?amount=100000"
# → address: litc1q...
# → amount: 100000
# → network: mainnet
```

### Send from URI

```bash
litc wallet send-uri "litc:litc1q...?amount=100000"
# equivalent to: litc wallet send litc1q... 100000
```

## Comparison with BIP-21

| Aspect | BIP-21 (Bitcoin) | LiTC URI |
|--------|-------------------|----------|
| Scheme | `bitcoin:` | `litc:` |
| Amount unit | BTC (decimal) | satoshis (integer) |
| Address types | P2PKH, P2SH, bech32 | ML-DSA-2 (bech32m) |
| Address length | ~34-62 chars | ~40 chars |
| Network encoding | In address prefix | In address prefix |
| Payment requests | `r=` parameter | `r=` parameter (reserved) |
| QR content | URI string | URI string |

## Security notes

- **Amount in satoshis, not LIT.** Avoids floating-point ambiguity.
- **Label and message are informational.** They are NOT signed or on-chain.
- **ML-DSA-2 addresses are ~40 characters.** QR codes handle this trivially.
- **No `r=` in QR by default.** Payment requests (BIP-70 style) require HTTPS
  and are a separate flow. QR should encode the address directly.
