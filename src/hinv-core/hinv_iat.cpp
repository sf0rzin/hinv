#include "hinv_iat.hpp"
#include "hinv_kmem.hpp"
#include <iostream>
#include <cwctype>
#include <algorithm>

namespace hinv {
namespace iat {

const std::vector<std::string> UserModeBypassDlls = {
    "hyperlog.dll",
    "hyperhv.dll",
    "hypertrace.dll",
    "kdserial.dll",
    "libhyperdbg.dll",
    "hyperevade.dll",
    "hyperperf.dll",
    "script-engine.dll",
    "symbol-parser.dll"
};

bool IsUserModeModule(const std::string& moduleName) {
    std::string lower = moduleName;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const auto& dll : UserModeBypassDlls) {
        if (lower.find(dll) != std::string::npos) return true;
    }
    return false;
}

uint64_t ResolveImportProcedure(byovd::IByovdBackend* backend, const std::string& moduleName,
                                const std::string& procedureName) {
    if (!backend || IsUserModeModule(moduleName)) return 0;

    // Normalize module name to a known kernel module.
    std::wstring modName(moduleName.begin(), moduleName.end());
    std::transform(modName.begin(), modName.end(), modName.begin(), ::towlower);

    size_t slash = modName.find_last_of(L"\\/");
    if (slash != std::wstring::npos) modName = modName.substr(slash + 1);
    size_t dot = modName.find(L'.');
    if (dot != std::wstring::npos) modName = modName.substr(0, dot);

    if (modName == L"ntoskrnl") modName = L"ntoskrnl.exe";
    else if (modName == L"hal") modName = L"hal.dll";
    else if (modName == L"fltmgr") modName = L"fltmgr.sys";
    else modName += L".sys";

    return kmem::ResolveKernelExport(backend, modName.c_str(), procedureName.c_str());
}

} // namespace iat
} // namespace hinv
