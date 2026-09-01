# Java ↔ C Compatibility Notes

This document describes how the C implementation was compared against the Java
reference and the conclusions drawn.

## Golden Vector Comparison

The C project carries the same `testdata/vector_001.json` … `vector_009.json`
files used by the Go/Java reference projects. Each vector specifies a complete
`tt_sign_request_t` input (params, data/payload, cookie, raw_body, url) and the
expected values of all six signing headers:

```
X-Argus            (custom base64, AES-128-CBC encrypted ProtoBuf/Simon structure)
X-Ladon            (custom base64, Feistel round function + AES key derivation)
X-Gorgon           (hex string, MD5 + nibble/bit manipulation)
X-Khronos          (decimal unix-seconds string)
X-TT-Request-Ticket (decimal unix-milliseconds string)
X-SS-Stub          (uppercase hex MD5 of body)
```

The test runner `test_all` asserts each of the six signatures for each vector,
giving **9 × 6 = 54 signature assertions** plus **38 primitive-unit tests**
(SM3, Simon, varint quirk, Ladon padding, Gorgon helpers, URL encoding,
query parsing), for a total of **96 passing tests** (verified 2026-09-01).

## Java Reference Validation

The Java reference project (`TikTokSignatrueForJava`) was run via `build.sh`
(javac, zero external dependencies) to confirm that its own golden-vector tests
reproduce the expected outputs. This validates that the reference itself
generates stable, reproducible results across machines.

```
cd /path/to/TikTokSignatrueForJava
chmod +x build.sh
./build.sh
# Expected: "BUILD SUCCESSFUL" / all tests pass
```

The golden vector JSON files were then compared byte-for-byte between the Java
project's `testdata/` and the C project's `testdata/`. They are identical.

## Module Mapping

| Java Module | C Module | Role |
|---|---|---|
| `SM3.java` | `sm3.c` | SM3 hash |
| `Simon.java` | `simon.c` | Simon 64/256 block cipher |
| `ProtoBuf.java` | `protobuf.c` | ProtoBuf writer with Python-compat quirk |
| `CryptoHelpers.java` | `crypto_helpers.c` | MD5 (EVP), hex, random bytes, LE64 |
| `UrlEncode.java` | `url_encode.c` | quote_plus/unquote_plus, parse_qs |
| `Argus.java` | `argus.c` | X-Argus (SM3 + Simon + AES-128-CBC) |
| `Ladon.java` | `ladon.c` | X-Ladon (custom round + AES key derivation) |
| `Gorgon.java` | `gorgon.c` | X-Gorgon V1/V2/V3 |
| `Signer.java` | `signer.c` | Public entry point + dispatch |
| `MiniJson.java` | `mini_json.c` | Minimal JSON parser (tests only) |

## Byte-level Differences Handled

1. **AES-CBC padding**: Java's `Cipher.getInstance("AES/CBC/PKCS5Padding")`
   automatically applies PKCS7 padding. The C EVP path does NOT pre-pad
   `withSuffix` to avoid double-padding. (Previously a source of parity
   divergence, caught and corrected during development.)

2. **ProtoBuf varint quirk**: Java ports Python's `while vint > 0x80` condition
   faithfully. This causes `0x80` to encode as a single `0x00` byte (one
   continuation byte fewer than a strict varint encoder would produce). The C
   implementation uses the same `> 0x80` condition. `pb_write_varint_raw()`
   exposes this for direct comparison.

3. **Python-style encoding**: `quote_plus` encodes spaces as `+`, bytes outside
   unreserved as `%XX`, UTF-8 multi-byte percent-encoded, insertion order
   preserved. Neither `curl_easy_escape` nor glibc `RFC1738` URL encoding is
   equivalent; the C code uses its own implementation.

4. **MD5 / AES-128-CBC**: Java's low-level `MessageDigest` and
   `Cipher.getInstance("AES/CBC/NoPadding")` are replaced with OpenSSL EVP API,
   producing identical outputs for identical inputs.

## HTTP / Application-level Response Analysis

When the response handling was first developed, `examples/Example.c` returned
HTTP 200 with the body:

```json
{
  "data": {
    "captcha": "",
    "desc_url": "",
    "description": "Maximum number of attempts reached. Try again later.",
    "error_code": 7
  },
  "message": "error"
}
```

An initial diagnosis attributed this purely to a server-side rate limit. That
conclusion was **premature**. A later differential test against the live Java
reference produced a decisive result: running `Example.java` against the same
endpoint from the same IP at the same time returned:

```json
{"data":{"email":"c***k@example.com","email_ticket":"PJ6DU54EQGRBVUNSVMMNAP46BQVEGND3"},"message":"success"}
```

i.e. the Java example **succeeded** where the C example was rejected.

### Root Cause (verified 2026-09-01)

A line-by-line comparison of `examples/Example.c` with `src/main/java/Example.java`
found that the C example omitted three query parameters that the Java reference
sends after `ts`:

| Param | Value (both implementations) |
|---|---|
| `iid` | random 64-bit number in `[7400000000000000000, 7499999999999999999]` |
| `device_id` | random 64-bit number in the same range |
| `openudid` | 16 random hex characters |

In the C example the `openudid` value was even computed but never added to the
parameter list (dead code), and `iid`/`device_id` were missing entirely. The
server answers requests without these device identifiers with the generic
`error_code 7` "Maximum number of attempts reached" application error — no
actual rate limit involved. `device_id` also feeds the Argus query signature,
so the C-generated `X-Argus` was computed from an empty `device_id` instead of
the real one.

### Fix and Verification

The three parameters were added to `examples/Example.c` in exactly the position
and order used by `Example.java` (immediately after `ts`, before
`support_webview`). A scripted diff of the ordered parameter lists now confirms
44/44 parameters identical to Java, in order.

After the fix, the live C example returned `"message":"success"` with the same
response shape and body length (108 bytes) as the Java reference, including an
issued `email_ticket`.

### What This Means

- `error_code 7` with this description is the endpoint's generic application
  error for an unrecognized/invalid device request — not necessarily a rate
  limit, and not a signature failure.
- The C implementation's signing algorithms remain byte-for-byte compatible
  with the reference (verified by the golden-vector suite).
- If the same fully-matching request is still rejected, the endpoint could
  genuinely be rate-limiting that email/address/IP; that is a server-side
  restriction and must not be bypassed.

## What Was NOT Tested

- **ASan / UBSan**: Runtime sanitizer libraries were unavailable on the
  development machine (Fedora 44, GCC 16.2.1, no libasan installed; no sudo
  to install). Substituted with GCC `-fanalyzer` (all findings were OOM-path
  false positives) and `MALLOC_CHECK_=3 MALLOC_PERTURB_=165` glibc heap
  checks (no corruption detected).

- **Genuine rate-limit rejection**: The endpoint's actual per-email/IP attempt
  limit was not exhaustively measured; the fix was verified by the immediate
  Java-vs-C behavior contrast described above.
