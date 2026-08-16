#pragma once
#include <windows.h>
#include <winternl.h>
#include <string>
#include <cstdint>
#include <vector>

#include "hinv_byovd.hpp"

namespace hinv {
namespace maintenance {

struct MaintenanceResult {
    // Not available for post-unload processing on current builds (layout is
    // build-dependent and
    // the array is written at unload time). Handled instead by
    // PrepareDriverUnload in the backend's unload path.
    bool mmUnloadedDrivers = false;
    bool piDdbCache = false;
    bool hashBucketList = false;
    bool wdFilter = false;
    std::wstring error;
    bool wdFilterPresent = false;
    // True only when every applicable maintenance operation completed successfully.
    bool complete = false;
};

struct DriverUnloadState {
    bool armed = false;
    uint64_t nameFieldVa = 0;
    UNICODE_STRING originalName{};
};

// Process traces of a loaded driver in kernel bookkeeping structures.
// driverFileTimestamp is the TimeDateStamp of the vulnerable driver's PE
// header (needed for the PiDDBCacheTable AVL lookup).
MaintenanceResult ProcessDriverTraces(byovd::IByovdBackend* backend, const std::wstring& driverName,
                                      uint32_t driverFileTimestamp);

// Read the TimeDateStamp from a driver file's PE header on disk. 0 on failure.
uint32_t GetDriverFileTimestamp(const std::wstring& driverPath);

// Zero the driver name in the vulnerable driver's own KLDR_DATA_TABLE_ENTRY so
// MiRememberUnloadedDriver skips it at unload time (kdmapper approach). Must be
// called while the driver is still loaded and the device handle is open; the
// backend calls this from its Shutdown before stopping the service.
bool PrepareDriverUnload(byovd::IByovdBackend* backend, HANDLE deviceHandle,
                         DriverUnloadState* state);
bool RestoreDriverUnload(byovd::IByovdBackend* backend,
                         DriverUnloadState& state);

// Direct helpers exposed for scripting.
bool ProcessUnloadedDriverEntry(byovd::IByovdBackend* backend, const std::wstring& driverName);
bool ProcessPiDddbCache(byovd::IByovdBackend* backend, const std::wstring& driverName, uint32_t driverFileTimestamp);
bool ProcessKernelHashBucketList(byovd::IByovdBackend* backend, const std::wstring& driverName);
bool ProcessWdFilterDriverList(byovd::IByovdBackend* backend, const std::wstring& driverName);

} // namespace maintenance
} // namespace hinv
