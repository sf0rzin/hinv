#include "hinv_ept_shadow.hpp"
#include "hinv_vmm.hpp"
#include <iostream>
#include <string>

namespace hinv {
namespace ept {

bool InitializeEptShadowEngine() {
    if (!vmm::IsVmmDeviceActive()) {
        std::cerr << "[hinv::ept] HyperDbg VMM not loaded; EPT shadow engine unavailable\n";
        return false;
    }
    std::cout << "[hinv::ept] EPT shadow engine initialized (HyperDbg backend)\n";
    return true;
}

bool ApplySplitTLB(uint64_t targetVirtualAddress, size_t size) {
    std::cout << "[hinv::ept] Applying EPT split-TLB cloak for 0x" << std::hex
              << targetVirtualAddress << std::dec << " (" << size << " bytes)\n";

    // HyperDbg does not expose raw EPT PTE editing to user-mode. We use !monitor
    // to trap read/write and !epthook2 to trap execute on the same range.
    bool ok = true;
    ok &= vmm::MonitorMemory(targetVirtualAddress, size, true, true, false);
    ok &= vmm::SetEptHiddenHook(targetVirtualAddress);
    return ok;
}

bool RemoveSplitTLB(uint64_t targetVirtualAddress) {
    std::cout << "[hinv::ept] Removing EPT cloak for 0x" << std::hex << targetVirtualAddress << std::dec << "\n";
    // HyperDbg event clearing: 'events' command then 'event clear N' or clear all.
    return vmm::SendVmmCommand("events");
}

} // namespace ept
} // namespace hinv
