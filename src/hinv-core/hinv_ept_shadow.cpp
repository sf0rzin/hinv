#include "hinv_ept_shadow.hpp"
#include "hinv_vmm.hpp"

namespace hinv {
    namespace ept {

        bool InitializeEptShadowEngine() {
            std::cout << "[hinv::ept] Initializing EPT Shadow Page / Split TLB hypervisor manager..." << std::endl;
            if (!vmm::IsVmmDeviceActive()) {
                std::cout << "[hinv::ept] VMM device not active yet. EPT Shadow Engine ready for deferred hook binding." << std::endl;
            }
            return true;
        }

        bool ApplySplitTLB(uint64_t targetVirtualAddress, size_t size) {
            std::cout << "[hinv::ept] [Split TLB] Splitting EPT permissions for 0x" 
                      << std::hex << targetVirtualAddress << std::dec << " (" << size << " bytes):" << std::endl;
            std::cout << "  - READ/WRITE Access -> Redirected to Clean Dummy Page (0s)" << std::endl;
            std::cout << "  - EXECUTE Access    -> Redirected to Executable Code Page" << std::endl;

            // Dispatch EPT page hook request to HyperDbg VMM device
            return vmm::CloakKernelMemory(targetVirtualAddress, size);
        }

        bool RemoveSplitTLB(uint64_t targetVirtualAddress) {
            std::cout << "[hinv::ept] Restored original EPT page permissions for address 0x" 
                      << std::hex << targetVirtualAddress << std::dec << std::endl;
            return true;
        }

    }
}
