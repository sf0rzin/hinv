#include "hinv_hijack.hpp"
#include "hinv_kmem.hpp"
#include <iostream>

namespace hinv {
namespace hijack {

uint64_t GetDriverObjectAddress(byovd::IByovdBackend* backend, const std::wstring& driverName) {
    if (!backend) {
        std::cerr << "[hinv::hijack] No BYOVD backend available\n";
        return 0;
    }

    std::wstring path = L"\\Driver\\" + driverName;
    uint64_t obj = kmem::GetDriverObject(backend, path.c_str());
    if (obj) {
        std::wcout << L"[hinv::hijack] \\Driver\\" << driverName << L" object at 0x" << std::hex << obj << std::dec << L"\n";
    } else {
        std::wcerr << L"[hinv::hijack] Failed to resolve \\Driver\\" << driverName << L"\n";
    }
    return obj;
}

bool PrepareHijackedDriverObject(byovd::IByovdBackend* backend, uint64_t targetDriverObjectAddress,
                                 uint64_t mappedDriverBase) {
    if (!backend || !targetDriverObjectAddress || !mappedDriverBase) return false;

    // The mapper performs the actual hijack before calling DriverEntry.
    // This function is kept as a public validation/logging hook.
    std::cout << "[hinv::hijack] Hijack context ready: DriverObject=0x" << std::hex
              << targetDriverObjectAddress << ", mapped base=0x" << mappedDriverBase << std::dec << "\n";
    return true;
}

} // namespace hijack
} // namespace hinv
