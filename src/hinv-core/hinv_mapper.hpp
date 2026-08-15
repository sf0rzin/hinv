#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>

#include "hinv_byovd.hpp"

namespace hinv {
namespace mapper {

struct MappingResult {
    bool     success = false;
    uint64_t imageBase = 0;
    uint64_t driverObject = 0;
    uint32_t driverEntryStatus = 0;
    uint32_t imageSize = 0;
    std::string error;
};

// Manually map a kernel driver (.sys) into kernel memory using the supplied BYOVD backend.
// When hijackNullDriverObject is true, DriverEntry receives the real
// DRIVER_OBJECT of \Driver\Null (recovered via handle enumeration) instead of
// a synthetic pool object — required by drivers that call IoCreateDevice
// (e.g. HyperDbg's hyperkd.sys), because the I/O manager refuses to open
// devices owned by a non-Object-Manager DRIVER_OBJECT. Caveats in hijack mode:
// null.sys's MajorFunction[]/DriverUnload stay overwritten until reboot, and
// DriverObject->DriverStart/DriverSize describe null.sys, not the mapped image
// (drivers that self-locate through them will misbehave).
MappingResult MapDriver(byovd::IByovdBackend* backend, const std::wstring& driverPath,
                        bool hijackNullDriverObject = false);

// Same, but accepts the raw file bytes already loaded in memory.
MappingResult MapDriverBytes(byovd::IByovdBackend* backend, const std::vector<uint8_t>& rawImage,
                             bool hijackNullDriverObject = false);

// Internal: build the mapped image (sections, relocations, imports) from raw
// PE bytes for the target kernel base. Fail-closed: returns false on any
// malformed structure. Exposed for unit tests.
bool BuildMappedImage(byovd::IByovdBackend* backend, const std::vector<uint8_t>& raw,
                      uint64_t imageBase, std::vector<uint8_t>& mapped);

} // namespace mapper
} // namespace hinv
