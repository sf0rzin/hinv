#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>

namespace hinv {
    namespace iat {
        // List of non-kernel user-mode DLLs to bypass/filter during IAT resolution for HyperDbg
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

        // Checks whether an imported DLL is a non-kernel user-mode library that should be bypassed
        bool IsUserModeModule(const std::string& moduleName);

        // Resolves kernel import procedure address while skipping user-mode stubs
        uint64_t ResolveImportProcedure(uint64_t kernelModuleBase, const std::string& moduleName, const std::string& procedureName);
    }
}
