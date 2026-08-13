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

    std::wstring modName = kmem::NormalizeModuleName(moduleName);
    return kmem::ResolveKernelExport(backend, modName.c_str(), procedureName.c_str());
}

} // namespace iat
} // namespace hinv
