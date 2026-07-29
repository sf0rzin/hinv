#include "hinv_iat.hpp"
#include <iostream>

namespace hinv {
    namespace iat {

        bool IsUserModeModule(const std::string& moduleName) {
            std::string lowerName = moduleName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

            for (const auto& bypassDll : UserModeBypassDlls) {
                if (lowerName.find(bypassDll) != std::string::npos) {
                    std::cout << "[hinv::iat] Bypassing non-kernel user-mode import dependency: " << moduleName << std::endl;
                    return true;
                }
            }
            return false;
        }

        uint64_t ResolveImportProcedure(uint64_t kernelModuleBase, const std::string& moduleName, const std::string& procedureName) {
            if (IsUserModeModule(moduleName)) {
                // Return dummy null address for bypassed user-mode imports
                return 0;
            }
            // Standard resolution continues for kernel modules (ntoskrnl.exe, hal.dll, FLTMGR.SYS)
            return kernelModuleBase;
        }

    }
}
