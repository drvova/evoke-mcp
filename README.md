# evoke-mcp

A Windows x64 MCP server with built-in Unicorn and KernEmul emulation, driver management, and
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
PE files or model a complete kernel. Named import bindings can use the explicit
API models and Windows host-snapshot bridges described below.

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
| `imports` | Up to 32 `{module, name, address, backend?}` bindings to named models or host-snapshot bridges. |
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
The same instruction/time budget spans API resumptions, with at most 256 API calls
per run. Entering a bound API counts as an observed hook entry; the model does not
execute the API's original machine instructions.

Each call has fresh state; there are no persistent sessions. One emulation runs
at a time per server, and another emulation request receives `emulation_busy`.
The translation buffer is configured to 16 MiB (Unicorn may adjust it). Unicorn
runs in the MCP process and guest memory is separate from host memory; this is
not an OS sandbox or a full-system virtual machine. See [third-party notices](THIRD_PARTY.md)
for the required engine's licensing.

## KernEmul Windows operations

The required `evoke-kernemul` worker compiles the original Windows handler
implementations from [noahware/kernemul](https://github.com/noahware/kernemul),
pinned to `cf3aedc6cc1755d2fedad77dcd4671bf045f9de8`. Its runtime registers
**618 operation names, including 157 Nt handlers and 157 Zw aliases**, across
`ntoskrnl.exe`, `fltmgr.sys`, `cng.sys`, `ci.dll`, `ndis.sys`, `tbs.sys`, `tdi.sys`,
and `win32k.sys`. These are registered names, not a claim of 618 independent,
complete implementations. Categories include memory, processes, threads,
synchronization, file I/O, registry, devices, security, and cryptography.

This backend complements the small raw-code models below. It executes the upstream
handlers with their shared guest object manager, memory manager, processes,
threads, registry, filesystem, and device model. No Windows image download is
needed for this image-free mode. The adapter changes registration/bootstrapping
and disables automatic symbol downloads; it retains the original operation bodies.
The registry and files start from upstream's synthetic boot state.

- `get_windows_emulation_info` reports worker availability and execution limits.
- `list_windows_operations` discovers the actual compiled handler registry, with
  optional `module`, exact `name`, and `syscalls_only` filters. Pagination uses
  `offset` and `limit` (default 100, maximum 200) and returns `next_offset`.
  Entries expose argument counts, return-value presence, and provenance.
- `emulate_windows_operations` executes up to 64 named calls in a fresh guest.
  State is shared across operations in that request and discarded afterward.
  Choose `context: "kernel"` (default) or `"user"`; virtual-memory syscalls that
  require a user process use the user context. All arguments follow the Windows
  x64 ABI; additional arguments such as varargs are allowed up to 16 total.

For example, allocate guest pool memory, copy supplied bytes into it, and inspect
those bytes through the original `MmCopyMemory` implementation:

```json
{
  "name": "emulate_windows_operations",
  "arguments": {
    "buffers": [
      { "id": "source", "bytes_hex": "01020304" },
      { "id": "copied", "size": 8 }
    ],
    "operations": [
      { "name": "ExAllocatePool2", "arguments": [64, 4, 1] },
      { "name": "MmCopyMemory", "arguments": [
        { "result": 0 }, { "buffer": "source" }, 4, 2, { "buffer": "copied" }
      ] }
    ],
    "reads": [{ "address": { "result": 0 }, "size": 4 }]
  }
}
```

Arguments accept unsigned integers/hex strings, `{ "buffer": "id", "offset": 0 }`
for guest pointers, `{ "result": 0 }` for an earlier non-void return value, or
`{ "read_u64": { "buffer": "handle" } }` for an output handle/pointer. Use hex
strings for full-width values, including `"0xffffffffffffffff"` for the current
process pseudo-handle. Buffer IDs are unique; buffers are zero-filled beyond
`bytes_hex`, and `size` may reserve more space. There are at most 32 buffers,
16 KiB each and 64 KiB total.

`patches` can relocate pointers inside structures before the first call:
`{ "buffer": "unicode_string", "offset": 8, "value": { "buffer": "text" } }`
writes a little-endian 64-bit pointer at that offset. Up to 64 patches are allowed;
each must fit within its destination buffer. Buffers are allocated before patches,
and reported `before_hex` includes these relocations. This lets clients construct
structures such as `UNICODE_STRING` and `OBJECT_ATTRIBUTES`. Use the pinned
upstream's x64 types and the operation's argument contract.

Results include `operation_trace`, resolved arguments, raw `return_value` (null
for void routines), before/after buffers, optional `reads` (at most 16, 16 KiB each,
64 KiB total), bounded upstream `diagnostics`, and the exact revision. `handled`
means the handler ran; inspect its return value for NTSTATUS failure and its
warnings for approximations. Unknown operations, bad guest addresses and thrown
handler errors are explicit errors. Earlier guest effects are not rolled back.

Nt/Zw routines are invoked **by name**, using the same original handler bodies;
this interface does not build an OS-specific numeric syscall table or execute PE
images. It does not run the guest scheduler. Calls that move the current guest PC,
sleep, wait, suspend, or finish the current thread stop with `guest_scheduling_required`.
Guest callbacks, additional queued threads, and some image/global-dependent paths
need further execution support. Upstream unsupported branches and approximations
remain. This is not complete Windows compatibility.

The worker is built by default and runs as a separate bounded process, with one
active request per server, a default 3-second deadline (100–10,000 ms configurable),
and a 128 KiB request / 1 MiB response cap. Timeout kills and reaps the worker.
Windows uses a job object with a 2 GiB process-memory limit and one process; Linux
uses a 2 GiB address-space limit plus CPU/output limits. These are resource limits,
not an OS sandbox. Supplied operations receive guest addresses; they have no live
MCP driver backend, automatic host filesystem import, or symbol-server downloads.
The native Windows snapshot and explicit live-driver tools remain separate paths.

## Windows API models and real host data

The raw-code backend supports both guest models and native Windows queries through
an explicit routing layer. It has **22 supported API models/bridges**; the separate
KernEmul backend above provides the broader Windows operation runtime.
No unknown function is automatically forwarded to the host. Windows user-mode
APIs do not substitute for arbitrary kernel routines or a real driver's protocol.

The agent can discover the exact interface through:

- `list_api_models`: optional `module` and `name` filters; returns supported module
  names, the Windows x64 parameter/return contract, backend, availability, fidelity,
  and limitations for each API. Module matching is case-insensitive; API names are
  case-sensitive. Coverage is declared explicitly with
  `complete_windows_api_coverage: false`.
- `get_system_snapshot`: calls actual Windows `GetSystemTimePreciseAsFileTime`,
  `QueryPerformanceCounter`, `QueryPerformanceFrequency`, `GetTickCount64`,
  `GetNativeSystemInfo`, and `GlobalMemoryStatusEx`. Returns time, counters, uptime,
  processor/page information, and memory status. This is read-only, works without
  a driver, and reports unavailability on non-Windows hosts. Full-width values
  are decimal strings. Failure is reported rather than replaced with fake data.

### Routing a guest call

Pass `imports` to `emulate_region` to associate guest function addresses with API
names. These addresses are mapped as separate executable trampoline pages; they
cannot overlap supplied code, data, or the stack. Multiple bindings may share a
trampoline page, but duplicate addresses are rejected. The agent supplies the
resolved call addresses (and IAT memory if the code uses an IAT); PE import parsing
and automatic symbol/address discovery are not implemented.

For example, this calls the guest `RtlZeroMemory` model on four supplied bytes:

```json
{
  "name": "emulate_region",
  "arguments": {
    "code_hex": "48b80000300000000000ffd0c3",
    "registers": { "rcx": "0x200000", "rdx": 4 },
    "memory": [{ "address": "0x200000", "bytes_hex": "01020304" }],
    "imports": [{
      "module": "ntoskrnl.exe", "name": "RtlZeroMemory",
      "address": "0x300000", "backend": "model"
    }]
  }
}
```

The returned guest bytes are `00000000`. Each call is recorded in `api_trace`
with module/name, address, arguments, `backend`/`source`, result, guest effects,
status, and limitations. Model writes are API effects rather than CPU memory-hook
events; inspect `api_trace` and the returned before/after memory. Unknown bound
APIs stop with `unsupported_api` and their supplied names. Known models with invalid
arguments, missing/protected guest memory, or unavailable host queries stop with
`api_model_error`. There is no default-success stub. The optional `backend`
assertion must match the registered route and never changes an API's semantics.
Calls are dispatched outside Unicorn's C callbacks, then return through the
emulated Windows x64 stack. Native host pointers and guest addresses are never
interchanged, and these handlers never receive the live driver backend.

### Implemented models

| Backend | APIs |
| --- | --- |
| Guest memory | `memcpy`, `memmove`, `memset`, `RtlCopyMemory`, `RtlMoveMemory`, `RtlZeroMemory`, `RtlFillMemory`, `RtlCompareMemory` |
| Guest pool | `ExAllocatePoolWithTag`, `ExAllocatePool2`, `ExFreePool`, `ExFreePoolWithTag` |
| Host snapshot through kernel-compatible signatures | `KeQuerySystemTime`, `KeQuerySystemTimePrecise`, `KeQueryPerformanceCounter` |
| Host snapshot through Win32 signatures | `GetSystemTimeAsFileTime`, `GetSystemTimePreciseAsFileTime`, `QueryPerformanceCounter`, `QueryPerformanceFrequency`, `GetTickCount64`, `GetNativeSystemInfo`, `GlobalMemoryStatusEx` |

Guest memory transfers are limited to 64 KiB per call and respect emulated page
permissions. Copies reject overlapping ranges; moves support them. Pool models
use a deterministic 1 MiB guest-only pool at `0x50000000`, with allocations up to
64 KiB, page rounding, tag tracking, freeing, and address reuse. Pool pages must
not overlap input regions when pool APIs are bound. Exhaustion returns NULL.
Invalid frees/tag mismatches stop the run; no Windows bugcheck, verifier, IRQL,
quota, synchronization, or complete pool metadata behavior is simulated. Pool
padding is mapped; this model is not an allocation-bounds checker. Uninitialized
allocations are represented by zero-filled guest pages. Legacy pool types are
limited to 0, 1, and 512, with a nonzero tag; `ExAllocatePool2` supports one of 0x40/0x80/0x100,
optionally ORed with 0x2. Unsupported flags/arguments stop with a model error rather
than reproduce every native error or exception path.

Host-backed guest calls capture a read-only snapshot at the first such call and
reuse it for the run, including time/counter values. The response includes the
snapshot and its provider; per-call provenance is `source: host_snapshot` with
fidelity `host_snapshot_bridge` in the catalog. This is actual host data adapted
to the guest ABI, **not execution of the named kernel export**. The native provider
requires Windows 8+ APIs and Windows x64 structure layouts (`SYSTEM_INFO`: 48 bytes,
`MEMORYSTATUSEX`: 64 bytes with guest `dwLength=64`). On Linux these bridges are
unavailable; portable tests inject a clearly labeled fixture provider. The agent
can still use all guest-only models there.

The third path remains the existing live-driver tools, with their validation and
audit workflow. Guest models modify only guest state, host-snapshot APIs only read
the host, and live driver operations are issued explicitly through their own tools.

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

Use CMake 3.20+, Git, a C++23 compiler with `std::format` (GCC 14+ or current
Visual Studio 2022), a C compiler, and OpenSSL development libraries. Windows also
needs the Windows SDK. KernEmul and its patched Unicorn revision, JSON, spdlog,
raw_pdb, the PE parser, and IA-32 definitions are downloaded at pinned revisions
with SHA-256 verification; see `cmake/kernemul/dependencies.json`.
Only the x86 architecture family is compiled. The worker is required, with no
emulation-free build. `cpp-httplib` remains included in the repository.

On Windows, use vcpkg's toolchain to provide OpenSSL, for example:

```powershell
cmake -S . -B build -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_MANIFEST_DIR="$PWD/cmake/kernemul"
cmake --build build --config Release --parallel 2
ctest --test-dir build -C Release --output-on-failure
```

Keep `build/Release/driver-mcp.exe`, `evoke-kernemul.exe`, and its OpenSSL runtime
DLLs together. The worker is located beside the server executable, never through
an agent-supplied executable path. The existing x64 Visual Studio solution also
builds the worker with CMake and copies it beside the server; it requires CMake on
PATH and vcpkg integration. Win32 builds are unsupported.

On Linux (all core and Windows model tests run without a real driver):

```sh
# Install GCC 14+ and the platform's OpenSSL development package first.
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

The tests cover typed conversion boundaries, failed reads and writes, stale bytes,
process lifetime changes, expiry, replay, competing requests, audit failures, and
HTTP origin/host/token validation. Management tests also cover capability gating,
attachment, metadata, allocation/protection results, audit failures, and preview
invalidation. A separate suite executes real Unicorn instruction streams and
checks arithmetic, calls/returns, high virtual addresses, guest memory writes,
faults, external instructions, loop budgets, and strict input validation. A third
suite tests API dispatch, guest pool state, named failures, provenance, snapshot
bridges, and actual native Windows system queries in Windows CI. The Windows
runtime suite executes original KernEmul handlers for pool allocation/copy,
process/thread lookup, event signaling, registry create/set/query, guest file
write/read, device creation, user virtual-memory allocation/free, and state
isolation. No suite
exercises a real kernel driver.

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
