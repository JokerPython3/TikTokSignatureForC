# TikTokSignatureForC

A **native C port** of the TikTok signing pipeline, ported from the local **Java**
implementation (`TikTokSignatrueForJava`), which itself was ported from the local
**Go** implementation, which in turn was ported from the Python
[SignerPy](https://github.com/is-L7N/SignerPy) project.

```
SignerPy (Python)
        ↓
Go port (SignerPyInGoLang/tiktok-signature)
        ↓
TikTokSignatrueForJava (Java port)
        ↓
TikTokSignatureForC (C port — this project)
```

This is an independent, behavior-compatible port. It does **not** call the
Python, Go, or Java implementations at runtime; every algorithm (SM3, Simon
64/256, ProtoBuf, AES-128-CBC, the Ladon round function, the Gorgon variants,
MD5) is re-implemented from scratch in C. The Java project is the reference/oracle
only.

## Author / Maintainer

S1

GitHub:
github.com/JokerPython3

## Attribution

This C project is a port of the local Java implementation
(`TikTokSignatrueForJava`), which is a port of the local Go implementation
(`SignerPyInGoLang/tiktok-signature`), which is based on the original SignerPy
Python project authored by **L7N** (`https://github.com/is-L7N/SignerPy`). The
C port does not claim ownership of the original SignerPy project. Upstream
attribution and licensing are preserved.

## What This Project Does

The port re-implements the signing pipeline so a C program can produce the same
signed header values as the Java (and Go) reference. A single public entry
point, `tt_sign()`, returns the six signed header values:

| Header | Role |
|---|---|
| `X-Argus` | Application-level request signature (SM3, Simon, ProtoBuf, AES-128-CBC). |
| `X-Ladon` | Device/request signature (custom round function with an MD5-derived key). |
| `X-Gorgon` | Anti-abuse signature; variants `8404` (V1), `8402` (V2), `4404`/`0` (V3). |
| `X-Khronos` | Unix timestamp (seconds) linked to the Gorgon signature. |
| `X-TT-Request-Ticket` | Unix timestamp (milliseconds) linked to the Gorgon signature. |
| `X-SS-Stub` | Uppercase MD5 of the URL-encoded request body. |

Every value is verified byte-for-byte against the deterministic golden vectors
(`testdata/vector_*.json`) used by the Go/Java projects, covering all nine
fixtures (V1/V2/V3 gorgon variants, empty bodies, UTF-8, cookies, and
multi-block AES/SM3 inputs) across all six signatures — 54 signature
assertions plus 42 primitive-unit tests for a total of **96 passing tests**.

## Requirements

- **C11 compiler** (GCC/Clang). The build compiles with `-std=c11` (no GNU
  extensions; some files define `_POSIX_C_SOURCE 200809L` for `strdup`,
  `strtok_r`).
- **CMake 3.16+**.
- **OpenSSL 3.x** (link target `OpenSSL::Crypto`) — required. MD5 and
  AES-128-CBC use the OpenSSL EVP API (the low-level MD5/AES APIs are
  deprecated in OpenSSL 3.0).
- **libcurl** — optional, only needed to build and run the `example` target.
  If libcurl is not found, CMake reports a warning and skips the example.
- **Linux / BSD / macOS** — the `example` makes real network calls. The library
  itself is pure C and only uses `time()`, `getenv()`, and `/dev/urandom`
  (falling back to `rand()`) for randomness.

### Build

```bash
cd TikTokSignatureForC
cmake -S . -B build
cmake --build build          # builds libtiktoksignature.a, test_all, example
```

Resulting artifacts in `build/`:

- `libtiktoksignature.a` — the static library.
- `test_all` — the test runner (pass the `testdata` path as `argv[1]`).
- `example` — the libcurl example.

### Test

```bash
ctest --test-dir build --output-on-failure       # runs test_all with testdata
# or, directly:
./build/test_all /path/to/TikTokSignatureForC/testdata
```

The suite covers the individual primitives (SM3, Simon, ProtoBuf varint
quirk, URL encode/decode, query parsing, Gorgon helpers, Ladon padding) and
all nine golden vectors, comparing every one of the six signatures
byte-for-byte against the reference output.

A stricter "quality gate" build that treats warnings as errors is available:

```bash
cmake -S . -B build-strict -DCMAKE_C_FLAGS="-Wall -Wextra -Wpedantic -Werror"
cmake --build build-strict
```

**CMakePresets** are also provided for convenience:

```bash
cmake --preset debug                # debug build (build-debug/)
cmake --preset release              # optimized build (build-release/)
cmake --preset strict               # warnings-as-errors build (build-strict/)
cmake --build --preset debug        # build the debug preset
ctest --preset default --output-on-failure
```

### Run the example

```bash
echo "you@example.com" | ./build/example
# or interactively to type the email:
./build/example
```

It builds the same request as `Example.java`, prints the six signing headers,
sends the request with libcurl, and reports both the HTTP transport status and
the application-level response status separately. Set `DEBUG=1` in the
environment for extra diagnostics (URL, method, body length — no secrets).

## Debugging

Set the `DEBUG` environment variable to `1` to enable diagnostic output from the
example:

```bash
DEBUG=1 ./build/example
```

When enabled, the example prints:

- HTTP method, URL (truncated), content type, body length
- Names of the signature headers sent (no sensitive values)
- A request-built confirmation

The debug output intentionally avoids printing signature header values (they are
session material), cookies, API keys/tokens, or the user-supplied email beyond
the stdin prompt.

## API Usage

```c
#include "tiktoksignature/signer.h"

tt_param_t params[] = {
    {"device_id", "7442000000000000001"},
    {"version_name", "41.9.3"},
    {"aid", "1233"},
};
tt_param_t data[] = {
    {"type", "3736"},
};

tt_sign_request_t req = {0};
req.params = params;
req.params_count = 3;
req.data = data;
req.data_count = 1;

tt_sign_options_t opts = {0};
opts.timestamp = 1700000000;   /* unix seconds; leave 0 + has_timestamp=false for now */
opts.has_timestamp = true;
opts.aid = 1233;
opts.version = 8404;

tt_signatures_t sig = tt_sign(&req, &opts);
/* sig.x_argus, sig.x_ladon, sig.x_gorgon, sig.x_khronos,
   sig.x_tt_request_ticket, sig.x_ss_stub  — all char* (NUL-terminated) */
tt_signatures_free(&sig);
```

### Input model

- `tt_sign_request_t.params` — ordered query parameters, or set `url` and leave
  `params` NULL to derive them from the URL (split at `?`).
- `tt_sign_request_t.data` — ordered form-body parameters (used to compute
  `X-SS-Stub`).
- `tt_sign_request_t.payload` — alias of `data` (used when `data` is empty).
- `tt_sign_request_t.cookie` — optional ordered cookie pairs (fed into X-Gorgon).
- `tt_sign_request_t.raw_body` — optional pre-encoded body string used verbatim.

All pointer members may be NULL with a count of 0. The library never modifies
the caller's strings; it URL-encodes internally with `url_encode_params()`
(urllib-compatible `quote_plus` semantics, insertion order preserved).

### Error handling

`tt_sign()` always returns a valid `tt_signatures_t`. Check the `error` field
to detect failures before accessing the strings:

```c
tt_signatures_t sig = tt_sign(&req, &opts);
if (sig.error != TT_SIGN_OK) {
    fprintf(stderr, "sign failed: error %d\n", sig.error);
    /* sig.x_argus etc. are NULL on failure */
    tt_signatures_free(&sig); /* still safe to call */
    return 1;
}
```

| Error code | Meaning |
|---|---|
| `TT_SIGN_OK` (0) | Success — all six strings are valid. |
| `TT_SIGN_ERR_NULL_INPUT` (1) | `req` or `opts` is NULL. |
| `TT_SIGN_ERR_BAD_VERSION` (2) | `opts.version` is not a recognized gorgon variant. |
| `TT_SIGN_ERR_ALLOC` (3) | An internal allocation failed (out of memory). |

`tt_signatures_free(NULL)` is safe and performs no operation.

### Options

`tt_sign_options_t` is zero-initialized for defaults, plus flags:

| Field | Default | Meaning |
|---|---|---|
| `timestamp` / `has_timestamp` | now | Unix epoch **seconds** (drives X-Khronos and X-TT-Request-Ticket). |
| `aid` | `1233` | App id. |
| `license_id` | `1611921764` | License id. |
| `sdk_version` | `"v05.00.06-ov-android"` | SDK version string. |
| `sdk_version_int` | `167775296` | SDK version int. |
| `version` | `0` (→ `4404` V3) | Gorgon variant: `8404`, `8402`, `4404`, or `0`. |
| `gorgon_byte3` / `has_gorgon_byte3` | random | Pin X-Gorgon byte 3. |
| `gorgon_byte7` / `has_gorgon_byte7` | random | Pin X-Gorgon byte 7. |
| `argus_rand` / `has_argus_rand` | random | Pin Argus field 3. |
| `ladon_random` / `has_ladon_random` | random | Pin the 4 X-Ladon random bytes. |

Use the `has_*` overrides for deterministic, reproducible tests.

## Project Structure

```
TikTokSignatureForC/
├── CMakeLists.txt               # build: libtiktoksignature.a, test_all, example
├── CMakePresets.json            # debug / release / strict presets
├── README.md                    # this document
├── .gitignore
├── .env.example                 # DEBUG / TARGET_URL example configuration
├── include/tiktoksignature/     # public headers
│   ├── param.h                  # tt_param_t (key/value pair)
│   ├── signer.h                 # tt_sign() / tt_signatures_t / tt_sign_request_t / tt_sign_options_t
│   ├── argus.h, ladon.h, gorgon.h
│   ├── sm3.h, simon.h, protobuf.h, crypto_helpers.h
│   ├── url_encode.h, mini_json.h
├── src/
│   ├── signer.c                 # public entry point + gorgon dispatch + stub
│   ├── argus.c                  # X-Argus (SM3 + Simon + ProtoBuf + AES-128-CBC)
│   ├── ladon.c                  # X-Ladon (custom round function + key derivation + base64)
│   ├── gorgon.c                 # X-Gorgon variants 8404 / 8402 / 4404
│   ├── sm3.c                    # SM3 hash
│   ├── simon.c                  # Simon 64/256 cipher
│   ├── protobuf.c               # ProtoBuf writer (Python-compatible varint quirk)
│   ├── crypto_helpers.c         # MD5 (EVP) / hex / /dev/urandom / LE64 helpers
│   ├── url_encode.c             # quote_plus / unquote_plus / encodeParams / parse
│   └── mini_json.c              # minimal JSON parser (test fixture reading + response parsing)
├── examples/
│   └── Example.c                # libcurl example (reads email from stdin, app-level response parsing)
├── tests/
│   └── test_all.c               # 96 unit + golden-vector assertions
├── docs/
│   └── COMPATIBILITY.md         # Java↔C port mapping, HTTP diagnosis, what was not tested
└── testdata/                    # golden vectors (mirror of the Java/Go project)
    ├── vector_001.json … vector_009.json
    └── python_request.json
```

## Algorithm Notes

- **SM3** — standard SM3 hash (IV `0x7380166F …`, round constants `0x79CC4519` /
  `0x7A879D8A`), 64-byte blocks, big-endian message-length suffix.
- **Simon 64/256** — 64-bit block, 256-bit key, 72 rounds, with the fixed
  round-constant `Z = 0x3DC94C3A046D678B`.
- **ProtoBuf varint** — ports the Python reference's 32-bit mask and its
  `> 0x80` loop-condition quirk (e.g. `0x80` encodes as a single `0x00` byte).
  The public helper `pb_write_varint_raw()` mirrors Java's `ProtoBuf.writeVarint`.
- **AES-128-CBC** — OpenSSL EVP with PKCS7 padding. The reference Java
  `Cipher` pads automatically, so the C side must NOT pre-pad `withSuffix`
  (a double-padding bug was caught and fixed during development).
- **URL encoding** — `quote_plus` semantics (spaces as `+`, `%XX` for other
  bytes, UTF-8 multi-byte percent-encoding, insertion order preserved). Do not
  substitute `curl_easy_escape()` or glibc `RFC1738` encoding for signing
  inputs.

## Troubleshooting

### HTTP 200 with error_code 7 / "Maximum number of attempts reached"

The TikTok `passport/email/send_code` endpoint returns HTTP 200 with an
application-level JSON error for requests it considers invalid:

```json
{"data":{"error_code":7,"description":"Maximum number of attempts reached. Try again later."},"message":"error"}
```

**Verified root cause (2026-09-01):** the C example was generating a request that
omitted the `iid`, `device_id`, and `openudid` query parameters that the Java
reference sends. The server treats such requests as coming from an unrecognized
device and answers with this generic error — it is **not** a signature failure
and, in this case, **not** an actual rate limit. Proof: the Java reference
(which sends those parameters) received `"message":"success"` from the same IP
moments later, and the C example began returning `"message":"success"` from the
same IP immediately after the parameters were added.

The fix, matching the Java reference in `Example.java`:

- `iid` — random 64-bit value in `[7400000000000000000, 7499999999999999999]`
- `device_id` — random 64-bit value in the same range (also consumed by the
  Argus query signature)
- `openudid` — 16 random hex characters

Added directly after `ts`, exactly where the Java example inserts them. See
`docs/COMPATIBILITY.md#http--application-level-response-analysis` for the full
differential diagnosis.

If you still see `error_code 7` with a fully matching request, the endpoint may
genuinely be rate-limiting that email/address/IP — that is a server-side
application restriction, not a signing bug.

## Memory Ownership

- All strings returned inside `tt_signatures_t` are heap-allocated; free them
  with `tt_signatures_free()`.
- `parse_query_params()` and `quote_plus()`/`unquote_plus()` return
  heap-allocated results; free each element with `free_query_params()` /
  `free()`.
- JSON values from `mini_json` are owned by the root value; call `json_free()`
  on the root returned by `json_parse()` exactly once.

## Privacy / Security

All fixtures and examples are sanitized and must not contain real credentials,
cookies, tokens, or private account information. Values are synthetic. Never
commit passwords, session cookies, access tokens, API keys, or personal account
credentials. Treat `X-Argus`/`X-Ladon`/`X-Gorgon` and any cookies as sensitive
session material. This repository contains no real secrets. The `.env` file is
ignored by git; copy `.env.example` to `.env` for local configuration only.

## License

This project is a C port based on the Java implementation, which is based on
the Go implementation, which is itself based on the Python SignerPy project.

- **Original SignerPy** — authored by **L7N**
  (`https://github.com/is-L7N/SignerPy`), distributed under the MIT license. Its
  copyright/license notice reads `copyright 2025 aythor : L7N`. The original
  project's rights and license are preserved and not modified by this port.
- **Go port** — written by **S1** (`https://github.com/JokerPython3`).
- **Java port** — written by **S1** (`https://github.com/JokerPython3`).
- **This C port** — written by **S1** (`https://github.com/JokerPython3`) as an
  independent C implementation re-implementing the algorithms from scratch.

The upstream SignerPy license terms are preserved. See the upstream SignerPy
repository for the authoritative license text.