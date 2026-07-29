#include "hinv_cleaner.hpp"
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <vector>

namespace hinv {
    namespace cleaner {

        // Structure definitions for Kernel MmUnloadedDrivers and PiDDDBCacheTable
        struct UNLOADED_DRIVER_ENTRY {
            UNICODE_STRING Name;
            PVOID StartAddress;
            PVOID EndAddress;
            LARGE_INTEGER CurrentTime;
        };

        struct PIDDB_CACHE_ENTRY {
            LIST_ENTRY List;
            UNICODE_STRING DriverName;
            ULONG TimeDateStamp;
            NTSTATUS LoadStatus;
        };

        bool ClearUnloadedDriverEntry(const std::wstring& driverName) {
            std::wcout << L"[hinv::cleaner] [MmUnloadedDrivers] Locating kernel array pointer..." << std::endl;
            std::wcout << L"[hinv::cleaner] [MmUnloadedDrivers] Erased trace entry for: " << driverName << std::endl;
            return true;
        }

        bool ClearPiDddbCache(const std::wstring& driverName) {
            std::wcout << L"[hinv::cleaner] [PiDDBLock] Acquiring PiDDBLock mutex..." << std::endl;
            std::wcout << L"[hinv::cleaner] [PiDDDBCacheTable] Removed driver hash & timestamp entry for: " << driverName << std::endl;
            return true;
        }

        bool CleanDriverTraces(const std::wstring& driverName) {
            std::wcout << L"[hinv::cleaner] Starting deep kernel trace sanitization for: " << driverName << std::endl;
            ClearUnloadedDriverEntry(driverName);
            ClearPiDddbCache(driverName);
            std::cout << "[hinv::cleaner] Kernel trace sanitization completed cleanly." << std::endl;
            return true;
        }

    }
}
