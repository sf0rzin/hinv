#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

#include "hinv_byovd.hpp"

namespace hinv {
namespace iat {

// HyperDbg / user-mode DLLs that should not be resolved as kernel imports.
extern const std::vector<std::string> UserModeBypassDlls;

bool IsUserModeModule(const std::string& moduleName);

// Resolve a kernel import using the BYOVD backend. Returns 0 if unresolved.
uint64_t ResolveImportProcedure(byovd::IByovdBackend* backend, const std::string& moduleName,
                                const std::string& procedureName);

} // namespace iat
} // namespace hinv
