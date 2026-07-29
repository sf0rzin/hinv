# hinv (Hyper Invisible)

> **Hyper-Invisible kernel manual mapping loader & VT-x/EPT stealth debugging framework.**

`hinv` is a high-performance hybrid framework combining Ring 0 BYOVD kernel manual mapping and Ring -1 VT-x/EPT hypervisor technology. It enables stealthy kernel driver loading, deep kernel trace sanitization, and hardware-assisted memory cloaking operating invisibly under Ring 0 security monitors.

---

## Key Features

1. **DriverObject Hijacking (`null.sys`):**
   - Resolves native `\Driver\Null` (`null.sys`) kernel base addresses to supply valid `PDRIVER_OBJECT` contexts during `DriverEntry`.
   - Prevents Page Faults and BSODs when drivers call `IoCreateDevice` / `IoCreateSymbolicLink` to register I/O control devices (such as `\\.\HyperDbgDebuggerDevice`).

2. **Non-Kernel IAT Dependency Bypass:**
   - Intelligent PE Import Address Table (IAT) filter that automatically ignores user-mode DLL dependencies (`hyperlog.dll`, `hyperhv.dll`, `hypertrace.dll`, `kdserial.dll`, `libhyperdbg.dll`) while mapping kernel exports (`ntoskrnl.exe`, `hal.dll`).

3. **EPT Shadow Pages / Split TLB Memory Cloaking:**
   - Leverages VT-x EPT engine to split page permissions:
     - **Read/Write Access:** Redirected to clean dummy pages (all `0`s).
     - **Execute Access:** Redirected to actual executable code pages in Ring 0.

4. **Deep Kernel Trace Sanitizer:**
   - Cleans driver traces from `MmUnloadedDrivers` array and `PiDDDBCacheTable` / `PiDDBLock` to leave zero residual logs in kernel structures.

5. **Headless Execution & Named Pipe IPC:**
   - Operates 100% silently in background without interactive CLI windows.
   - Listens on Named Pipe `\\.\pipe\hinv_headless` for dynamic IPC control.

6. **Header-Only C++ Client SDK (`hinv_client.hpp`):**
   - Lightweight C++ header for seamless integration into external research tools.

---

## Repository Structure

```
hinv/
├── CMakeLists.txt         # Build configuration
├── README.md              # Project documentation & Manual
└── src/
    ├── hinv-core/
    │   ├── hinv_hijack.hpp / .cpp
    │   ├── hinv_iat.hpp / .cpp
    │   ├── hinv_vmm.hpp / .cpp
    │   ├── hinv_cleaner.hpp / .cpp
    │   ├── hinv_ept_shadow.hpp / .cpp
    │   ├── hinv_client.hpp
    │   └── headless/
    │       ├── hinv_headless.hpp / .cpp
    └── hinv-cli/
        └── main.cpp
```

---

## User Manual & Usage Guide

### 1. Building `hinv`

#### Using MSVC Developer Command Prompt:
```cmd
cl /std:c++20 /EHsc /DUNICODE /D_UNICODE /Fe:hinv.exe src/hinv-cli/main.cpp src/hinv-core/hinv_hijack.cpp src/hinv-core/hinv_iat.cpp src/hinv-core/hinv_vmm.cpp src/hinv-core/hinv_cleaner.cpp src/hinv-core/hinv_ept_shadow.cpp src/hinv-core/headless/hinv_headless.cpp psapi.lib advapi32.lib
```

#### Using CMake:
```cmd
cmake -B build
cmake --build build --config Release
```

---

### 2. Command Line Usage

#### **A. Load Unsigned Driver (BYOVD Manual Mapping)**
Loads an unsigned `.sys` driver into kernel memory using BYOVD with DriverObject hijacking:
```cmd
hinv.exe load C:\path\to\your_driver.sys
```

#### **B. Run in Silent Headless Mode**
Runs `hinv` quietly in background executing an automated HyperDbg script:
```cmd
hinv.exe headless --script script.txt
```

#### **C. Check System & Hypervisor Status**
```cmd
hinv.exe status
```

---

### 3. Headless Scripting Syntax Example (`script.txt`)

```text
# Connect to local kernel debugging
.connect local

# Activate VT-x VMM engine
load vmi

# Apply EPT Split TLB memory cloaking
splittlb 0x7ff612340000 4096

# Sanitize vulnerable driver traces
clean RTCore64.sys

# Monitor syscalls for specific process PID (e.g. 0x2e18)
!syscall pid 0x2e18

# Exit interactive pipe session
exit
```

---

### 4. C++ Client SDK Integration (`hinv_client.hpp`)

Include `hinv_client.hpp` in your research project to dynamically control `hinv` via Named Pipe IPC:

```cpp
#include "hinv_client.hpp"

int main() {
    hinv::Client client;

    // Connect to active hinv IPC server
    if (client.Connect()) {
        // Apply EPT Shadow Pages cloaking
        client.SetupSplitTLB(0x7FF612340000, 4096);

        // Sanitize kernel trace logs
        client.CleanKernelTraces("RTCore64.sys");

        // Send custom HyperDbg command
        client.SendCommand("!syscall pid 0x2e18");
    }
    return 0;
}
```

---

## License

Distributed under the MIT License. See `LICENSE` for more information.
