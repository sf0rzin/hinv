# hinv (Hyper Invisible)

> **Real BYOVD kernel manual mapping loader with kernel trace sanitization and HyperDbg integration.**

**For educational purposes only.** This project is intended for authorized kernel security research, malware analysis, and red-team training in controlled environments. Using it against systems you do not own or without explicit permission is illegal and unethical.

`hinv` is a Windows kernel research framework that loads unsigned `.sys` drivers into kernel memory through a vulnerable signed driver (BYOVD), resolves imports/relocations, hijacks `\Driver\Null` for `DriverEntry`, sanitizes `MmUnloadedDrivers` / `PiDDBCacheTable`, and talks to HyperDbg over its real IOCTL interface.

This repo was originally a README-driven placeholder. It has been rewritten to perform the actual operations it advertises.

---

## What works today

1. **BYOVD backend abstraction**
   - Loads a vulnerable driver as a service, opens its device, and exposes arbitrary kernel read/write.
   - Supports `dbutil_2_3.sys` (Dell) out of the box; profile is auto-detected from the file name.
   - Designed so additional backends (gdrv, RTCore64, etc.) can be added in `hinv_byovd.cpp`.

2. **Kernel execution primitive**
   - Uses `HalDispatchTable[1]` overwrite + `NtQueryIntervalProfile` to run small Ring-0 stubs.
   - Stubs are placed in a writable kernel page, the PTE NX bit is cleared, and everything is restored after execution.
   - Used for `ExAllocatePool2`/`ExAllocatePoolWithTag`, `ObReferenceObjectByName`, and calling `DriverEntry`.

3. **Real manual mapper**
   - Parses the target PE in usermode.
   - Allocates kernel memory, copies sections, fixes base relocations, resolves imports from `ntoskrnl.exe` / `hal.dll` / etc.
   - Writes the prepared image to kernel memory.
   - Resolves `\Driver\Null` and calls the mapped driver's `DriverEntry(DriverObject, NULL)`.

4. **Kernel trace sanitizer**
   - Locates `MmUnloadedDrivers` and `PiDDBCacheTable` by exported symbol or signature fallback.
   - Zeros matching `UNLOADED_DRIVER_ENTRY` records and unlinks `PIDDB_CACHE_ENTRY` nodes.

5. **HyperDbg integration**
   - Opens `\\.\HyperDbgDebuggerDevice`.
   - Sends real HyperDbg IOCTLs (`IOCTL_INIT_VMM`, `IOCTL_SEND_USER_DEBUGGER_COMMANDS`, etc.).
   - Wraps common commands such as `!epthook2` and `!monitor`.

6. **Headless mode + named-pipe IPC**
   - Loads BYOVD once and listens on `\\.\pipe\hinv_headless`.
   - Processes commands: `load`, `clean`, `splittlb`, `hypercmd`, `status`, `exit`.
   - `hinv_client.hpp` provides a header-only C++ SDK.

---

## Repository structure

```
hinv/
├── CMakeLists.txt
├── README.md
└── src/
    ├── hinv-core/
    │   ├── hinv_byovd.hpp / .cpp      # BYOVD driver loader + read/write primitives
    │   ├── hinv_kmem.hpp / .cpp       # kernel export resolution, shellcode exec, allocator
    │   ├── hinv_hijack.hpp / .cpp     # DriverObject hijack helpers
    │   ├── hinv_iat.hpp / .cpp        # import filtering / resolution utility
    │   ├── hinv_vmm.hpp / .cpp        # HyperDbg device + IOCTL commands
    │   ├── hinv_cleaner.hpp / .cpp    # MmUnloadedDrivers / PiDDB sanitizer
    │   ├── hinv_ept_shadow.hpp / .cpp # EPT cloak wrappers via HyperDbg
    │   ├── hinv_mapper.hpp / .cpp     # manual PE mapper
    │   ├── hinv_client.hpp            # header-only IPC client SDK
    │   └── headless/
    │       ├── hinv_headless.hpp / .cpp
    └── hinv-cli/
        └── main.cpp
```

---

## Build

### Requirements

- Windows SDK / WDK headers
- CMake >= 3.20 or MSVC developer prompt
- A vulnerable signed driver binary (e.g. `dbutil_2_3.sys`) for BYOVD operations

### CMake

```cmd
cmake -B build -A x64
cmake --build build --config Release
```

### MSVC (single command)

```cmd
cl /std:c++20 /EHsc /DUNICODE /D_UNICODE /Fe:hinv.exe ^
  src/hinv-cli/main.cpp ^
  src/hinv-core/hinv_byovd.cpp ^
  src/hinv-core/hinv_kmem.cpp ^
  src/hinv-core/hinv_hijack.cpp ^
  src/hinv-core/hinv_iat.cpp ^
  src/hinv-core/hinv_vmm.cpp ^
  src/hinv-core/hinv_cleaner.cpp ^
  src/hinv-core/hinv_ept_shadow.cpp ^
  src/hinv-core/hinv_mapper.cpp ^
  src/hinv-core/headless/hinv_headless.cpp ^
  psapi.lib advapi32.lib ntdll.lib
```

---

## Usage

### Load an unsigned driver via BYOVD

```cmd
hinv.exe load C:\path\to\target.sys --byovd C:\path\to\dbutil_2_3.sys
```

### Clean kernel traces left by a vulnerable driver

```cmd
hinv.exe clean dbutil_2_3.sys --byovd C:\path\to\dbutil_2_3.sys
```

### Send a command to HyperDbg

```cmd
hinv.exe hypercmd "!syscall pid 0x2e18"
```

### Run headless with a script

```cmd
hinv.exe headless --byovd C:\path\to\dbutil_2_3.sys --script script.txt
```

Example `script.txt`:

```text
# load a driver manually
load C:\path\to\target.sys

# clean traces of the BYOVD driver
clean dbutil_2_3.sys

# ask HyperDbg to monitor a region
hypercmd !monitor rw 0xFFFFF80000000000 0x1000

# exit the engine
exit
```

### SDK client example

```cpp
#include "hinv_client.hpp"

int main() {
    hinv::Client client;
    if (client.Connect()) {
        client.LoadDriver("C:\\path\\to\\target.sys");
        client.CleanKernelTraces("dbutil_2_3.sys");
        client.HyperDbgCommand("!syscall pid 0x2e18");
    }
    return 0;
}
```

---

## Architecture notes

- The BYOVD backend is the root of trust. Everything else is built on top of arbitrary kernel read/write.
- Kernel memory allocation and code execution are implemented through `HalDispatchTable` stubs rather than relying on a driver-specific execution IOCTL. This makes the framework backend-agnostic at the kernel-exec layer.
- The manual mapper builds the driver image in usermode and only needs two kernel execution events: one to allocate pool memory and one to call `DriverEntry`.
- EPT / split-TLB is intentionally delegated to HyperDbg. Writing a bare-metal VT-x hypervisor is outside the scope of a single repo; HyperDbg already provides the VMM engine and exposes it through IOCTLs.

---

## Known limitations

- `dbutil_2_3.sys` IOCTL structure varies by build. If the read/write primitive fails, verify the input layout in `hinv_byovd.cpp` against your specific driver version.
- `MmUnloadedDrivers` / `PiDDBCacheTable` signatures are Windows-version dependent. Export resolution is tried first; if symbols are not exported, the signature fallback may need adjustment for newer builds.
- The PTE self-reference index is assumed to be `0x1ED`. Windows can randomize this on some builds.
- HyperDbg must already be loaded (`hyperdbg-cli --start` or equivalent) for VMM/EPT commands to work.

---

## License

Distributed under the MIT License. See `LICENSE` for more information.
