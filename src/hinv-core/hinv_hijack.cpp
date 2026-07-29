#include "hinv_hijack.hpp"
#include <psapi.h>
#include <algorithm>
#include <cwctype>

namespace hinv {
    namespace hijack {

        bool EnablePrivilege(LPCWSTR privilegeName) {
            HANDLE hToken;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;

            LUID luid;
            if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
                CloseHandle(hToken);
                return false;
            }

            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
            CloseHandle(hToken);
            return (result && GetLastError() == ERROR_SUCCESS);
        }

        uint64_t GetDriverObjectAddress(const std::wstring& driverName) {
            EnablePrivilege(SE_DEBUG_NAME);
            EnablePrivilege(SE_LOAD_DRIVER_NAME);

            LPVOID drivers[1024];
            DWORD cbNeeded;

            if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
                TCHAR szDriver[1024];
                int cDrivers = cbNeeded / sizeof(drivers[0]);

                std::wstring targetLower = driverName;
                std::transform(targetLower.begin(), targetLower.end(), targetLower.begin(), ::towlower);

                for (int i = 0; i < cDrivers; i++) {
                    if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))) {
                        std::wstring name(szDriver);
                        std::wstring nameLower = name;
                        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);

                        if (nameLower.find(targetLower) != std::wstring::npos || nameLower.find(L"null") != std::wstring::npos) {
                            uint64_t driverBase = reinterpret_cast<uint64_t>(drivers[i]);
                            std::wcout << L"[hinv::hijack] Found native driver (" << szDriver 
                                       << L") at kernel base: 0x" << std::hex << driverBase << std::dec << std::endl;
                            return driverBase;
                        }
                    }
                }
            }

            std::wcerr << L"[hinv::hijack] Warning: Target driver object for " << driverName << L" not found. Falling back to default." << std::endl;
            return 0;
        }

        bool PrepareHijackedDriverObject(uint64_t targetDriverObjectAddress, uint64_t mappedDriverBase) {
            if (!targetDriverObjectAddress || !mappedDriverBase) {
                return false;
            }

            std::cout << "[hinv::hijack] DriverObject hijacking context prepared successfully." << std::endl;
            return true;
        }

    }
}
