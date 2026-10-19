# evoke-mcp

A Windows x64 MCP server with built-in Unicorn emulation, driver management, and
typed memory access through a compatible local kernel driver. It exposes
authenticated Streamable HTTP at `http://127.0.0.1:8888/mcp`.

## Built-in code-region emulation

Unicorn **is a required dependency in every build**. The `get_emulation_info` and
`emulate_region` tools are always registered, including when no driver or process
is connected. There is no plugin installation or enable/disable option.

`emulate_region` runs supplied x86-64 machine-code bytes with an initial register
state and explicitly supplied guest memory. This is useful for inspecting a
selected routine or code section extracted from a driver binary. The emulator has
no driver-backend reference: it neither reads nor modifies live kernel/process
memory, and no driver source is required for the supplied bytes. It does not load
PE files, resolve imports, supply Windows kernel APIs, or model a complete kernel.

For example, this computes `7 + 35` and returns `rax: "0x2a"`:

```json
{
  "name": "emulate_region",
  "arguments": {
    "code_hex": "4889c84801d0c3",
    "registers": { "rcx": 7, "rdx": 35 },
    "instruction_limit": 100,
    "timeout_ms": 100
  }
}
```

Arguments:

| Field | Meaning |
| --- | --- |
| `code_hex` | Required contiguous hex bytes, up to 16 KiB of x86-64 code. |
| `address` | Guest code address; defaults to `0x100000`. High kernel virtual addresses are supported. |
| `entry_offset` | Byte offset within the supplied code where execution begins; defaults to zero. |
| `registers` | Initial general-purpose registers, `rflags`, `fs_base`, and `gs_base`. Unknown names are rejected. |
| `memory` | Up to eight `{address, bytes_hex, permissions}` guest regions, at most 4 KiB of supplied bytes each. Permissions are `r`, `rw` (default), `rx`, or `rwx`. |
| `instruction_limit` | Maximum instructions: default 10,000, maximum 100,000. |
| `timeout_ms` | Unicorn execution timeout: default 100 ms, maximum 500 ms. |
| `trace_limit` | Maximum entries in each trace: default 128, maximum 512. |

Addresses and register values accept unsigned JSON integers or decimal / `0x`
strings; use strings to preserve full-width values in JavaScript clients. Limits
require JSON integers. The code is mapped read/execute. Guest memory maps are
rounded to 4 KiB pages and their remaining bytes are zero-filled. Regions sharing
a page with each other, the code, or the default stack are rejected. All mappings
are guest virtual addresses, without live or emulated Windows page-table walks.

A fresh 64 KiB read/write stack is mapped at `0x70000000` for each call. Default
`rsp` is `0x7000ffd8`, with a synthetic return address pointing to the end of the
supplied code and space for the Windows x64 calling convention. Overriding `rsp`
requires supplying the appropriate guest memory and return state yourself.

Results include final registers and RIP as hex strings, instruction addresses and
bytes, memory-access attempts, before/after bytes for every explicit data region,
and a stop reason. `completed` means execution reached the end of the supplied
code (by falling through or returning to the synthetic address); it does not prove
that a real driver would behave identically. `instructions_observed` counts entry
into instruction hooks, including instructions subsequently stopped or faulted.
Truncation flags identify incomplete traces. Write values in the memory trace are
provided only for accesses at most eight bytes wide; returned guest bytes capture
the final state of supplied regions.

Unmapped/protected accesses report the address, size, and access type. System
calls, port I/O, interrupts, invalid instructions, and HLT stop execution instead
of forwarding to Windows or inventing kernel API results. Missing calls commonly
appear as an unmapped instruction fetch; the emulator reports the address and
does not infer the API name. Partial runs retain their trace and registers with
`isError: true`. Infinite loops stop at the instruction or execution-time budget.
These are execution limits, not a hard wall-clock deadline for request setup.

Each call has fresh state; there are no persistent sessions. One emulation runs
at a time per server, and another emulation request receives `emulation_busy`.
The translation buffer is configured to 16 MiB (Unicorn may adjust it). Unicorn
runs in the MCP process and guest memory is separate from host memory; this is
not an OS sandbox or a full-system virtual machine. See [third-party notices](THIRD_PARTY.md)
for the required engine's licensing.

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

The server starts with no target selected, and remains available if its device
cannot be opened. Use `get_driver_status`, then `connect_driver` if needed, then
`attach_process` with an explicit PID. After target exit, attach again. Process
memory operations require a connected driver and a queryable live process. No
kernel driver is included.

## Driver management and adapters

The MCP service uses the portable `memory_backend` interface; all Evoke-specific
IOCTLs, structures, and Windows page-protection flags live in the Windows adapter.
A common MCP API can support other drivers through additional adapters. **There
is no universal Windows driver ABI:** supplying another device name or arbitrary
IOCTL number cannot make an unknown driver compatible.

`get_driver_status` reports the adapter name, device availability, current process
identity, pending previews, and supported operations. These capabilities describe
what the adapter implements, not a runtime probe or a verified driver version.
Unsupported operations return `operation_not_supported_by_adapter` without issuing
a driver call. In addition to the four memory tools, the Evoke adapter exposes:

| Tool | Arguments | Behavior |
| --- | --- | --- |
| `get_driver_status` | none | Report capabilities and connection/target state. |
| `connect_driver` | none | Open the configured device (`\\.\evoke`); does not install or load it. |
| `attach_process` | `pid` | Attach to an explicit PID and retain its process lifetime. |
| `detach_process` | none | Request detachment and clear the selected target on success. |
| `get_process_info` | none | Return process identity, PEB, and DTB (full-width decimal strings). |
| `allocate_memory` | `size`, `protection` | Reserve and commit private process memory; return the allocated range. |
| `protect_memory` | `addr`, `size`, `protection` | Change page protection; return the actual range and previous native flags. |
| `unload_driver` | none | Request unload, then close the device on success. |

Protection names are `no_access`, `read_only`, `read_write`, `execute`,
`execute_read`, and `execute_read_write`. The adapter maps them to its native
flags. Executable page permissions do **not** execute code. Allocations select
an address automatically. Size must be a positive integer fitting the Windows
user address range; allocation/protection results may be rounded to page boundaries.
An invalid returned range or a changed process is an error even if the driver
reported success; the response preserves the returned range for inspection.

Management mutations run directly (no patch-preview step), are serialized with
memory operations, and are audited before and after dispatch. They invalidate
all pending memory patches, including when the driver call fails. A pre-operation
audit failure prevents dispatch and retains existing previews. Final audit errors
preserve `ok` and set `isError: true`; `operation_attempted` distinguishes dispatch
from validation/pre-audit rejection. A management failure does not prove the kernel
performed no work. On detach or unload failure the Evoke adapter disables local
memory access; detach retains the driver PID for a retry. Reattach before further
memory access. On success unload disconnects; load the driver externally before
reconnecting. A missing device or detached target does not require a server restart.
`/health` returns authenticated JSON diagnostics with HTTP 200 when the server is
reachable, including when the device is unavailable.

To add another driver, subclass `memory_backend`, implement identity/read/write,
and override `name`, `connected`, `supports`, and each supported management method.
Protection enums and process metadata are translated inside that adapter. Inject
it into `memory_service` in the entry point; MCP handlers need no driver-specific
changes. Optional methods default to unsupported. Only the Evoke adapter ships
currently, and its management ABI has not been tested against a real driver.

The supplied Evoke interface defines **no free-memory or general execution
operation**. Its `eac_call` declaration has no accompanying kernel handler, so it
is not exposed as a general executor. Status reports `execution_exposed: false` for live driver execution and
`emulation_available: true` for the built-in offline emulator. Live execution and
memory release require an adapter with an actual documented driver contract;
neither is implemented by guessing new IOCTLs.

## Build

Use CMake 3.20+, a C++20 compiler, and the Windows SDK / Visual Studio 2022 C++
build tools. CMake downloads nlohmann JSON 3.12.0 from a pinned, SHA-256-verified
archive, and builds the required Unicorn 2.1.4 engine from its own pinned,
SHA-256-verified archive. Only the x86 architecture family is compiled. A C
compiler is also required for Unicorn; there is no emulation-free build.
`cpp-httplib` remains included in the repository.

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The executable is `build/Release/driver-mcp.exe`. The existing Visual Studio
solution can also be built as **x64** after installing vcpkg and running
`vcpkg integrate install`; `vcpkg.json` supplies nlohmann JSON and Unicorn (use a current vcpkg checkout
with Unicorn 2.1.4). Win32 builds are
unsupported because the driver protocol and process addresses require x64.

The transaction core and mock-driver tests also build on Linux:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

The tests cover typed conversion boundaries, failed reads and writes, stale bytes,
process lifetime changes, expiry, replay, competing requests, audit failures, and
HTTP origin/host/token validation. Management tests also cover capability gating,
attachment, metadata, allocation/protection results, audit failures, and preview
invalidation. A separate suite executes real Unicorn instruction streams and
checks arithmetic, calls/returns, high virtual addresses, guest memory writes,
faults, external instructions, loop budgets, and strict input validation.
Neither suite exercises a real kernel driver.

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

After normal MCP initialization, select a process using these tool-call arguments:

```json
{ "name": "get_driver_status", "arguments": {} }
```

```json
{ "name": "attach_process", "arguments": { "pid": 1234 } }
```

Use a PID that exists on your machine. If status reports an unavailable device,
load your compatible driver externally and call `connect_driver` first. Then
prepare a patch:

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
