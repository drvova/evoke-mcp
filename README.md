# evoke-mcp

A Windows x64 MCP server for typed memory access through a compatible local kernel
driver. It exposes authenticated Streamable HTTP at `http://127.0.0.1:8888/mcp`.

## Verified memory patches

Memory writes now use two tools instead of `write_memory`:

1. **`prepare_memory_patch`** validates an address, primitive type, and proposed
   value, then reads the original bytes. It returns the process identity, before
   and after values and bytes, and a random patch ID. **Preparing never writes.**
   The optional `expected` value must match the current bytes.
2. Inspect the preview and decide whether to apply it. The MCP client should show
   the preview to its user before calling **`apply_memory_patch`** with that ID.
3. Apply checks that the same process lifetime and original bytes still match,
   writes once, and reads back the result. Only a matching readback reports
   `verified: true`.

IDs expire after 60 seconds, are held in memory, and are consumed on **every apply
attempt**, including failed attempts. At most 128 unexpired previews are kept.
Concurrent requests are serialized around driver access and patch state. Restarting
the server invalidates all previews. Patch IDs are references to previews, not
user approval credentials: the server does not enforce a human approval step.

Other tools are `read_memory` and `get_base_address`. Reads report driver failures
as errors rather than returning a misleading zero. Supported types are `byte`,
`u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`, `float`, and `double`.
Integer fields reject fractions, booleans, negative unsigned values, and overflow.
Floating values must be finite and representable without overflow or underflow to
zero; `float` rounds to its representable value, which is shown in the preview.
Addresses must be integers at least `0x10000`, and the entire transfer must fit in
the Windows x64 user address range. Memory values containing NaN or infinity
cannot be read or previewed as floating-point values; inspect their integer bits.
Use a client that preserves 64-bit JSON integers, or inspect the returned exact
little-endian hex bytes if the client uses JavaScript numbers.

The target is still selected in `driver-mcp/source/entry/main.cpp`, currently
`FortniteClient-Win64-Shipping.exe`. The server requires a working compatible
`\\.\evoke` driver and a queryable live process. No kernel driver is included.
Startup fails if the driver or target is unavailable; restart after target exit.

## Build

Use CMake 3.20+, a C++20 compiler, and the Windows SDK / Visual Studio 2022 C++
build tools. CMake downloads nlohmann JSON 3.12.0 from a pinned, SHA-256-verified
archive. `cpp-httplib` remains included in the repository.

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The executable is `build/Release/driver-mcp.exe`. The existing Visual Studio
solution can also be built as **x64** after installing vcpkg and running
`vcpkg integrate install`; `vcpkg.json` supplies nlohmann JSON. Win32 builds are
unsupported because the driver protocol and process addresses require x64.

The transaction core and mock-driver tests also build on Linux:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

The tests cover typed conversion boundaries, failed reads and writes, stale bytes,
process lifetime changes, expiry, replay, competing requests, audit failures, and
HTTP origin/host/token validation. They do not exercise a real kernel driver.

## Run and connect

Set `EVOKE_MCP_TOKEN` to a random token of at least 32 characters using only
letters, digits, `-`, and `_`. For example, in **PowerShell 7**:

```powershell
$env:EVOKE_MCP_TOKEN = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
.\build\Release\driver-mcp.exe
```

Configure your MCP client with:

- URL: `http://127.0.0.1:8888/mcp`
- Header: `Authorization: Bearer <the same EVOKE_MCP_TOKEN>`
- POST content type: `application/json`

Keep the token private. The server never prints it. All GET/POST endpoints,
including `/health`, require it. Browser origins are limited to exact `localhost`
and `127.0.0.1` hosts with optional valid ports. Host headers must address
`localhost:8888` or `127.0.0.1:8888`; CORS never uses a wildcard. OPTIONS requests
validate origin and host without requiring a token so browser preflight works.

After normal MCP initialization, the tool-call arguments are:

```json
{
  "name": "prepare_memory_patch",
  "arguments": { "addr": 65536, "type": "u8", "expected": 12, "value": 20 }
}
```

The address above is illustrative: supply a valid address in the attached process.
Inspect `structuredContent` (also included as JSON in the text result). To apply
that exact preview:

```json
{
  "name": "apply_memory_patch",
  "arguments": { "patch_id": "<patch_id returned by prepare>" }
}
```

## Outcomes and audit

Every apply result contains `status`, `verified`, `write_attempted`, process
identity, address, type, before/after bytes, and any observed bytes. Outcomes
include `memory_changed`, `target_changed`, `patch_expired`, `driver_read_failed`,
`driver_write_failed`, `verification_read_failed`, and `verification_failed`.
An unknown or consumed ID returns a tool error. Failures require a fresh preview.

The server appends an `apply_started` record before writing and an outcome record
after each recognized apply attempt to `evoke-mcp-audit.jsonl` in its working
directory. The log includes addresses and memory bytes; protect it appropriately.
If the pre-write audit append fails, no write is attempted. If the final append
fails, the returned outcome includes `audit_error` and `isError: true`, preserving
whether the write verified. Stream flushing is not a crash-durability guarantee;
an interrupted attempt may have only an `apply_started` record.

These are checked writes, **not atomic compare-and-swap**. The target can change
memory between checks or immediately after verification. A failed driver call can
still have partially changed memory. There is no automatic rollback, which could
overwrite a subsequent legitimate update. Verification establishes only the bytes
observed by the driver at readback time; it relies on a correct driver contract.
