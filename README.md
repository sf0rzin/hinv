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
| `hinv_byovd` | Loads a vulnerable signed driver as a service and exposes kernel read/write primitives. Currently supports `dbutil_2_3.sys`; additional backends can be added. |
| `hinv_kmem` | Kernel export resolution, SMAP-safe shellcode execution via `HalDispatchTable`, memory allocation (`ExAllocatePool2`), and driver object lookup (`ObReferenceObjectByName`). |
| `hinv_mapper` | Manual PE mapper: parses a `.sys` file, allocates kernel memory, copies sections, fixes relocations, resolves imports, and calls `DriverEntry`. |
| `hinv_cleaner` | Kernel trace sanitizer for `MmUnloadedDrivers` and `PiDDBCacheTable`, with lock acquisition (`PiDDBLock`). |
| `hinv_vmm` / `hinv_ept_shadow` | HyperDbg device integration and EPT cloak wrappers (`!epthook2`, `!monitor`). |
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
│  hinv_cleaner   │  ← MmUnloadedDrivers, PiDDBCacheTable
│  hinv_vmm/ept   │  ← HyperDbg IOCTLs
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   hinv_kmem     │  ← HalDispatchTable exec, pool alloc, exports
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   hinv_byovd    │  ← Service load + arbitrary kernel R/W
└─────────────────┘
```

The design follows a clear layering: the BYOVD backend provides the primitive, `hinv_kmem` builds kernel services on top, and the mapper/cleaner/VMM layers use those services to perform higher-level operations.

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

### Load an unsigned driver into a lab VM

```cmd
hinv.exe load C:\lab\test_driver.sys --byovd C:\lab\dbutil_2_3.sys
```

### Clean traces left by the vulnerable driver

```cmd
hinv.exe clean dbutil_2_3.sys --byovd C:\lab\dbutil_2_3.sys
```

### Run a headless automation script

```cmd
hinv.exe headless --byovd C:\lab\dbutil_2_3.sys --script script.txt
```

Example `script.txt`:

```text
# Load a driver into kernel memory
load C:\lab\test_driver.sys

# Remove traces of the vulnerable driver from kernel logs
clean dbutil_2_3.sys

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
        client.CleanKernelTraces("dbutil_2_3.sys");
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

## Known limitations

This is an **experimental prototype**. The following areas are incomplete or unstable:

- **PTE self-reference index** is hardcoded to `0x1ED`. Some Windows builds randomize this value.
- **PiDDBCacheTable traversal** only supports the classic `LIST_ENTRY` layout (Windows 7–10 21H2). Newer builds using `RTL_RB_TREE` require a dedicated traversal that is not yet implemented.
- **Driver object hijack** borrows `\Driver\Null`; a future improvement is allocating a synthetic `DRIVER_OBJECT`.
- **Vulnerable driver compatibility** varies by build. Verify the `dbutil_2_3.sys` IOCTL structure against your specific binary before use.
- **HyperDbg integration** uses structured packets for read/edit/VA2PA, but arbitrary script commands (`!syscall`, `!monitor`, etc.) require the full `libhyperdbg` script engine and are not yet supported.
- **EPT / split-TLB cloaking** is not implemented. The relevant functions return `false` to indicate the operation did not occur.
- **Named pipe security** uses a basic SYSTEM/Administrators ACL but does not validate client tokens.
- **Automated tests** cover PE parser safety; kernel-mode behavior is not automatically tested.

---

## Contributing

Contributions are welcome. If you add a new BYOVD backend, improve version detection, or extend the HyperDbg integration, please open a pull request with clear documentation and test notes.

---

## License

Distributed under the MIT License. See `LICENSE` for more information.
