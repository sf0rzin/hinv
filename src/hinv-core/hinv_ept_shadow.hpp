#pragma once
#include <windows.h>
#include <cstdint>
#include <cstddef>

namespace hinv {
namespace ept {

struct ShadowPageConfig {
    uint64_t guestVirtualAddress;
    uint64_t readWritePhysicalPage;
    uint64_t executePhysicalPage;
    size_t   pageSize;
    bool     isCloaked;
};

// Initialize the EPT shadow subsystem. Requires HyperDbg VMM to be loaded.
bool InitializeEptShadowEngine();

// Apply EPT-based memory cloaking via HyperDbg !epthook2 / !monitor.
// This is a user-mode control wrapper; the real split-TLB logic runs inside HyperDbg.
bool ApplySplitTLB(uint64_t targetVirtualAddress, size_t size);

// Remove EPT cloaking. Delegates to HyperDbg event modification commands.
bool RemoveSplitTLB(uint64_t targetVirtualAddress);

} // namespace ept
} // namespace hinv
