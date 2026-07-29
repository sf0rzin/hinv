#pragma once
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <string>

namespace hinv {
    namespace hijack {
        // Retrieves the kernel base address and PDRIVER_OBJECT pointer for \Driver\Null (null.sys)
        // or a specified native Windows driver to allow IoCreateDevice calls without BSOD.
        uint64_t GetDriverObjectAddress(const std::wstring& driverName = L"Null");

        // Prepares a hijacked DriverObject structure in kernel memory
        bool PrepareHijackedDriverObject(uint64_t targetDriverObjectAddress, uint64_t mappedDriverBase);
    }
}
