#pragma once
#include <windows.h>
#include <iostream>
#include <string>

namespace hinv {
    namespace cleaner {
        // Cleans driver entry traces from kernel structures (PiDDDB, MmUnloadedDrivers)
        bool CleanDriverTraces(const std::wstring& driverName);

        // Clears specific entry from MmUnloadedDrivers array
        bool ClearUnloadedDriverEntry(const std::wstring& driverName);

        // Clears entry from PiDDDBCacheTable
        bool ClearPiDddbCache(const std::wstring& driverName);
    }
}
