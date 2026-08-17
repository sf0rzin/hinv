# hinv — Hyper Invisible

> **Experimental Windows kernel security research and educational framework.**

`hinv` is an **open-source learning project** that combines the core concepts of **KDMapper** (driver loading without signature enforcement) and **HyperDbg** (hardware-assisted debugging). It is built to help students, reverse engineers, and security researchers understand how Windows kernel driver loading, manual PE mapping, and kernel trace management work at a low level.

**⚠️ This is an experimental prototype.** It is intended for **study and experimentation in isolated, disposable virtual machines only**. It demonstrates techniques documented in public Windows internals research, security conference talks, and open-source educational tools. It is not production-ready, not stable across Windows builds, and not safe to run on real systems. If you are learning about kernel drivers, BYOVD, or hypervisor-based debugging, this codebase gives you a working reference implementation you can read, build, and extend.

---

## Why this project exists

Windows kernel security is traditionally hard to learn because many resources are either purely theoretical or incomplete. `hinv` bridges that gap by providing:

- A **readable, modular C++ codebase** with clear separation between the BYOVD backend, kernel execution primitives, manual mapper, and trace sanitization logic.
- **Real Windows API and kernel-mode programming patterns** you can study: service control management, named pipes, PE parsing, relocation processing, and driver object manipulation.
- **Integration with HyperDbg** so you can observe kernel behavior through a hypervisor instead of relying only on static analysis.

Think of it as a lab toolkit: read the code, run it in a VM, break it, fix it, and learn how the pieces fit together.

---

## What is implemented

| Component | Description |
|-----------|-------------|
| `hinv_byovd` | Loads an explicitly supported vulnerable signed driver as a service and exposes kernel read/write primitives. Supports `dbutil_2_3.sys` and the reference `iqvw64e.sys` binary (Intel, kdmapper-compatible `CopyMemory` IOCTL); unknown names and unverified reference binaries are rejected. |
| `hinv_kmem` | Kernel export resolution, arbitrary kernel function calls via a temporary `ntoskrnl!NtAddAtom` prologue hook (kdmapper-style), pool allocation (`ExAllocatePoolWithTag`), and page protection changes (`MmSetPageProtection`). |
| `hinv_mapper` | Manual PE mapper: parses a `.sys` file, allocates kernel memory, copies sections, fixes relocations, resolves imports, and calls `DriverEntry`. |
| `hinv_maintenance` | Kernel trace maintenance: `PiDDBCacheTable` (AVL), `g_KernelHashBucketList` (ci.dll), `WdFilter` runtime driver list, and `MmUnloadedDrivers` prevention at unload time. Patterns ported from kdmapper, validated on Windows 11 26200. |
| `hinv_vmm` | HyperDbg device integration via structured IOCTL packets (read/edit memory, VA→PA, VMM init). |
| `hinv_headless` | Named-pipe IPC server and script executor for automated workflows. |
| `hinv_client` | Header-only C++ SDK for controlling a running headless instance. |

---

## Architecture

```
hinv-cli / hinv-client
        │
        ▼
┌─────────────────┐
│  hinv_headless  │  ← Named-pipe IPC server
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  hinv_mapper    │  ← PE parse, reloc, imports, DriverEntry
│  hinv_maintenance│ ← MmUnloadedDrivers, PiDDBCacheTable
│  hinv_vmm       │  ← HyperDbg IOCTLs
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   hinv_kmem     │  ← NtAddAtom hook calls, pool alloc, exports
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   hinv_byovd    │  ← Service load + arbitrary kernel R/W
└─────────────────┘
```

The design follows a clear layering: the BYOVD backend provides the primitive, `hinv_kmem` builds kernel services on top, and the mapper/maintenance/VMM layers use those services to perform higher-level operations.

---

## Building

### Prerequisites

- Windows 10/11 x64
- Visual Studio 2019+ (or MSVC build tools) **or** MinGW-w64 GCC
- CMake >= 3.20 (optional but recommended)

### With CMake

```cmd
cmake -B build -A x64
cmake --build build --config Release
```

### With MSVC directly

```cmd
cl /std:c++20 /EHsc /DUNICODE /D_UNICODE /Fe:hinv.exe ^
  src/hinv-cli/main.cpp ^
  src/hinv-core/hinv_byovd.cpp ^
  src/hinv-core/hinv_kmem.cpp ^
  src/hinv-core/hinv_iat.cpp ^
  src/hinv-core/hinv_vmm.cpp ^
  src/hinv-core/hinv_maintenance.cpp ^
  src/hinv-core/hinv_mapper.cpp ^
  src/hinv-core/headless/hinv_headless.cpp ^
  psapi.lib advapi32.lib ntdll.lib
```

---

## Usage

### Load an unsigned driver into a lab VM

Manual mapping, kernel allocation, protection changes, and trace processing require the Intel backend because they use its read-only physical-mapping primitive. The DbUtil backend is limited to plain kernel read/write operations.

```cmd
hinv.exe load C:\lab\test_driver.sys --byovd C:\lab\iqvw64e.sys
```

The Intel `iqvw64e.sys` backend is selected by its exact file name and the reference SHA256 is verified before loading:

```cmd
hinv.exe load C:\lab\test_driver.sys --byovd C:\lab\iqvw64e.sys
```

### Process traces left by the vulnerable driver

```cmd
hinv.exe process-traces iqvw64e.sys --byovd C:\lab\iqvw64e.sys
```

### Run a headless automation script

```cmd
hinv.exe headless --byovd C:\lab\iqvw64e.sys --script script.txt
```

Scripts stop on the first `ERR` response; `exit` ends the script and session. Trace processing returns a failure when any applicable structure was not confirmed.

Example `script.txt`:

```text
# Load a driver into kernel memory
load C:\lab\test_driver.sys

# Process traces of the vulnerable driver in kernel logs
process-traces iqvw64e.sys

# Shut down the engine
exit
```

### SDK client example

```cpp
#include "hinv_client.hpp"

int main() {
    hinv::Client client;
    if (client.Connect()) {
        client.LoadDriver("C:\\lab\\test_driver.sys");
        client.ProcessKernelTraces("iqvw64e.sys");
    }
    return 0;
}
```

### HyperDbg structured operations

HyperDbg text commands are not supported over raw IOCTL. Use the structured packet APIs:

```cpp
// Read kernel memory via HyperDbg
uint8_t buffer[256];
hinv::vmm::ReadKernelMemoryHyperDbg(0xFFFFF80000000000, buffer, sizeof(buffer));

// Edit kernel memory via HyperDbg
uint64_t value = 0xDEADBEEF;
hinv::vmm::EditKernelMemoryHyperDbg(0xFFFFF80000000000, &value, sizeof(value));

// Virtual to physical translation
uint64_t physical = 0;
hinv::vmm::VirtualToPhysicalHyperDbg(0xFFFFF80000000000, physical);
```

---

## Loading HyperDbg via hinv (lab/VM only)

`hyperkd.sys` (HyperDbg's kernel debugger) imports not only from `ntoskrnl.exe` but also from its companion kernel-mode DLLs (`hyperhv.dll`, `hyperlog.dll`, `hypertrace.dll`, `kdserial.dll`). Because manually mapped modules are invisible to the loaded-module list, hinv keeps a **process-local registry of mapped modules**: after each successful `load`, the module's file name and base address are registered, and import resolution checks this registry before falling back to normally loaded modules. This makes chain-mapping possible in a single invocation — companions first, `hyperkd.sys` last:

```cmd
hinv.exe load drivers\hyperhv.dll drivers\hyperlog.dll drivers\hypertrace.dll drivers\kdserial.dll drivers\hyperkd.sys --byovd drivers\iqvw64e.sys --null-drvobj
```

On the Windows 26200 lab build tested here, the compatibility switches are required:

```cmd
set HINV_LEGACY_ABSOLUTE_HOOK=1
set HINV_LEGACY_IFT_MUTATION=1
```

Prerequisites:

- A **disposable VM** (this is an educational prototype; expect instability).
- **Secure Boot off** and the **vulnerable-driver blocklist disabled** (or `iqvw64e.sys` will be blocked).
- **VT-x / EPT enabled** in the VM firmware for HyperDbg to run.
- The HyperDbg v0.23 binaries and `iqvw64e.sys` are **not** part of this repository; obtain them yourself. The reference `iqvw64e.sys` used during development is the public LOLDrivers sample with SHA256 `4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b`.

---

## Learning resources this project is based on

- **KDMapper** — manual mapping concepts and driver loading workflows.
- **HyperDbg** — hypervisor-assisted debugging and EPT-based observation.
- **Windows Internals** (Pavel Yosifovich, Mark Russinovich) — driver model, object manager, and memory manager internals.
- **Public BYOVD research** — Microsoft documentation on driver signature enforcement and the vulnerable driver landscape.

---

## Legal and ethical use

**This project is for educational purposes only.** It is designed for:

- Security research in isolated virtual machines
- Malware analysis and reverse engineering coursework
- Red-team training with explicit authorization
- Learning Windows kernel driver development and internals

Do not use this software on systems you do not own or without explicit written permission. Unauthorized use may violate computer misuse laws and Microsoft's terms of service. The authors and contributors are not responsible for misuse.

---

## Lab validation

The full pipeline must be exercised only inside a disposable VM with snapshots. Do not reproduce it on a real host machine:

1. Obtain `iqvw64e.sys` — the public [LOLDrivers sample](https://www.loldrivers.io/drivers/1d2cdef1-de44-4849-80e5-e2fa288df681/) (SHA256 `4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b`).
2. Build or pick any test `.sys` (a no-op `DriverEntry` returning `STATUS_SUCCESS` is enough).
3. From an elevated prompt:

```cmd
hinv.exe load C:\lab\test_driver.sys --byovd C:\lab\iqvw64e.sys
hinv.exe process-traces iqvw64e.sys --byovd C:\lab\iqvw64e.sys
hinv.exe headless --byovd C:\lab\iqvw64e.sys --script script.txt
```

For structured API coverage, build the lab-only smoke binary explicitly:

```cmd
cmake -S . -B build -DHINV_BUILD_LAB_SMOKE=ON
cmake --build build --target hinv_hyperdbg_api_smoke --parallel
build\lab\hinv_hyperdbg_api_smoke.exe --skip-init
```

Optional lab-only EPT monitor/execute-detour lifecycle probe:

```cmd
build\lab\hinv_hyperdbg_api_smoke.exe --skip-init --ept-smoke
```

Optional v0.23 script-engine compile/execute probe. Set
`HINV_LIBHYPERDBG_DIR` to the directory containing `libhyperdbg.dll`,
`script-engine.dll`, `symbol-parser.dll`, `pdbex.dll`, and `libipt.dll`:

```cmd
set HINV_LIBHYPERDBG_DIR=C:\lab\hinv-hyperdbg-full\hyperdbg-v0.23
build\lab\hinv_hyperdbg_api_smoke.exe --skip-init --script-smoke
```

For the complete disposable-VM matrix, combine the opt-in probes. The MSR
write probe writes the value read from core 0 back to IA32_TSC and is disabled
unless `HINV_ENABLE_MSR_WRITE=1` is also set:

```cmd
set HINV_ENABLE_MSR_WRITE=1
build\lab\hinv_hyperdbg_api_smoke.exe --skip-init --ept-smoke --script-smoke --msr-write-smoke
```

For trigger coverage without unsafe execution, use:

```cmd
build\lab\hinv_hyperdbg_api_smoke.exe --skip-init --ept-trigger-smoke --custom-trigger-smoke
```

The EPT read trigger is exercised. Execute-detour and custom-code execution
remain skipped unless `HINV_ENABLE_UNSAFE_HYPERDBG_TRIGGERS=1` is explicitly
set in the disposable VM.

Use `--close-session` only when the smoke process owns the VMM session; the
default `--skip-init` path leaves a shared headless session open.

MSR reads and virtual-memory search are enabled by default. MSR writes are
disabled unless `HINV_ENABLE_MSR_WRITE=1` is explicitly set in the disposable
lab VM.

The binary uses Win32/NT process APIs and exercises kernel reads, current-process
scratch reads/edits, VA-to-PA plus physical reads, page-table inspection, MSR
reads, virtual-memory search, event registration/action/cleanup, process
attach/detach and user-debugger pause/continue commands, cross-process
reads/edits, and PEB/image-base discovery. It edits only memory allocated for
the test processes;
it does not write arbitrary kernel addresses. Run it while the same interactive
headless session that initialized the VMM remains alive.
The process must run with `SeDebugPrivilege` available and enabled so Windows
returns kernel module base addresses.

- Set `HINV_TRACE=C:\lab\trace.log` for per-stage telemetry that survives a bugcheck (every line is flushed by close). When a run fails, the trace shows the last completed stage; when the machine bugchecks, Event ID 1001 in the `System` log carries the bugcheck code and the faulting address.
- Success looks like `DriverEntry returned 0x0` / `[+] Mapped at 0x...`. A completed pass logs `PiDDBCacheTable processed`, `g_KernelHashBucketList processed`, and `WdFilterDriverList processed` (skipped when WdFilter is not loaded).

Hard-won rules, baked in after live-fire debugging on Windows 11 26200:

- Never read a candidate/unmapped kernel VA through the backend "to see if it exists" — a BYOVD read of an unmapped address faults inside the vulnerable driver (bugcheck `0x50`). Resolve addresses from in-image code/data only.
- Any address derived from a pattern scan is validated against the owning module's image range before being used or called.
- MinGW builds link the C++ runtime statically: a foreign `libstdc++-6.dll` earlier in `PATH` (e.g. Git for Windows') ABI-crashes `std::fstream` at runtime.

---

## Known limitations

This is an **experimental prototype**. The following areas are incomplete or unstable:

- **Kernel execution primitive** no longer uses shellcode, `HalDispatchTable`, or the (randomized-per-boot) PTE self-reference index. Kernel functions are called through a temporary `ntoskrnl!NtAddAtom` hook written via the Intel backend's physical-mapping IOCTLs (`0x25`/`0x19`/`0x1A`), kdmapper-style. The normal entry patch is one aligned atomic 8-byte jump to an executable gate that rejects unrelated `KTHREAD`s. This requires a backend with atomic read-only writes — currently only `iqvw64e.sys`; the DbUtil backend can only read/write plain kernel memory. Some Windows 11 pool layouts place the gate outside the signed 32-bit jump range; the default path fails closed there. For a disposable lab VM only, `HINV_LEGACY_ABSOLUTE_HOOK=1` enables the legacy 12-byte absolute publication path, which is non-atomic and must not be used on a host or production system. The KTHREAD gate and read-back restoration checks remain active in that mode.
- A kernel call has three outcomes: not executed, executed and restored, or restoration uncertain. The last outcome retains all reachable allocations and aborts further kernel calls; it is never reported as success.
- **PsInvertedFunctionTable** is read-only by default. On builds without the supported `RtlAddFunctionTable` export, mapping an image with `.pdata` is rejected and its allocation is released. For the tested Windows build `26200` only, `HINV_LEGACY_IFT_MUTATION=1` enables the legacy direct insert/remove path needed by HyperDbg's manually mapped `.pdata`; the epoch counter is not a substitute for the private kernel writer lock, so this switch is lab-only and unsafe on hosts or other builds.
- **MmUnloadedDrivers** is not processed post-hoc (the array layout is build-dependent and only written at unload). Instead, the backend arms prevention at unload: the vulnerable driver's own `KLDR_DATA_TABLE_ENTRY` name is zeroed so `MiRememberUnloadedDriver` skips recording it (kdmapper approach).
- **PiDDBCacheTable / g_KernelHashBucketList / WdFilter** maintenance operations use kdmapper's patterns and locking discipline (`PiDDBLock` / `g_HashCacheLock` acquired via `ExAcquireResourceExclusiveLite`), resolved per build by pattern scan. If a pattern matches nothing on a future build, the maintenance path fails closed with a log line.
- **Driver object** is a minimal synthetic `DRIVER_OBJECT` allocated in kernel pool by default. With the legacy `--null-drvobj` flag, hinv calls `IoCreateDriver` so the mapped entry receives a real Object-Manager-owned object; it no longer hijacks `\Driver\Null`.
- **Vulnerable driver compatibility** varies by build. Two backends are implemented: `dbutil_2_3.sys` (plain kernel read/write only) and the reference `iqvw64e.sys` (kdmapper-compatible, `\\.\Nal` device, single `CopyMemory` IOCTL `0x80862007`; the public LOLDrivers sample with SHA256 `4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b`). Unknown names are rejected, and the Intel profile verifies this SHA256 before loading. The Intel backend supplies read/write plus the kdmapper physical-mapping helpers (`GetPhysicalAddress`/`MapIoSpace`/`UnmapIoSpace`), which power read-only memory writes for the `NtAddAtom` hook.
- **HyperDbg integration** targets the v0.23 SDK wire layouts for read/edit/VA2PA, page-table, MSR, search, event lifecycle, structured EPT monitor/execute-detour registration, process attach/detach and user-debugger command transport, including compiled script buffers, honoring HyperDbg's `DEBUGGER_OPERATION_WAS_SUCCESSFUL` (`0xFFFFFFFF`) status convention and per-value 8-byte-slot edit layout. The optional script smoke compiles and executes a v0.23 script against a paused user target.
- **HyperDbg script integration** optionally loads the v0.23 package's `script-engine.dll` and its exported `ScriptEngineParse`/`RemoveSymbolBuffer` functions. The companion `libhyperdbg.dll` is installed for the isolated HyperDbg runtime, but is not loaded into the raw-IOCTL process because its session manager would contend with hinv's shared VMM handle. Set `HINV_LIBHYPERDBG_DIR` before using `CompileUserScriptHyperDbg` or `ExecuteTextUserScriptHyperDbg`; the normal structured API path does not require these DLLs.
- **VMM initialization** is one-shot per VM boot on this HyperDbg build. Keep the initialized headless session alive for structured reads; a second process must reuse the active session and must not call `InitializeVmm` again. Headless scripts defer `initvmm` to a worker thread before publishing the IPC server because the HyperDbg v0.23 init path can block on the headless main thread.
- **EPT monitoring** has a lab-only structured probe (`--ept-smoke`) covering registration, break action, state query, execute-detour lifecycle against a kernel target, and cleanup. `--ept-trigger-smoke` additionally runs the real read `RunScript` trigger; execute-detour and `RunCustomCode` execution are explicitly gated by `HINV_ENABLE_UNSAFE_HYPERDBG_TRIGGERS=1` after reproducing kernel faults in the disposable VM. Event output/condition handling is covered at the packet/lifecycle level; text commands such as `!epthook2`/`!monitor` still require an isolated full interpreter session and are not dispatched through the raw-IOCTL process.
- **Named pipe security** restricts access to local SYSTEM/Administrators and rejects remote clients. A client with local administrator rights can still control the session.
- **Automated tests** cover PE parser safety (section/import/relocation/unwind bounds, fixed-base images, and malformed inputs are rejected fail-closed), refusal of unsynchronized IFT writes, and the SDK's timeout/result contract; kernel-mode behavior is not automatically tested.

---

## Contributing

Contributions are welcome. If you add a new BYOVD backend, improve version detection, or extend the HyperDbg integration, please open a pull request with clear documentation and test notes.

---

## License

Distributed under the MIT License. See `LICENSE` for more information.
