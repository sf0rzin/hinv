#pragma once
#include <windows.h>
#include <string>
#include <cstdint>
#include <vector>

#include "hinv_byovd.hpp"

namespace hinv {
namespace cleaner {

struct CleanResult {
    bool mmUnloadedDrivers = false;
    bool piDdbCache = false;
    std::wstring error;
};

// Remove traces of a loaded driver from kernel bookkeeping structures.
CleanResult CleanDriverTraces(byovd::IByovdBackend* backend, const std::wstring& driverName);

// Direct helpers exposed for scripting.
bool ClearUnloadedDriverEntry(byovd::IByovdBackend* backend, const std::wstring& driverName);
bool ClearPiDddbCache(byovd::IByovdBackend* backend, const std::wstring& driverName);

} // namespace cleaner
} // namespace hinv
