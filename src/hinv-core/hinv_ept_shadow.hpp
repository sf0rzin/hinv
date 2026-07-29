#pragma once
#include <windows.h>
#include <iostream>
#include <cstdint>

namespace hinv {
    namespace ept {

        // Structure representing EPT Split TLB / Shadow Page entry configuration
        struct ShadowPageConfig {
            uint64_t guestVirtualAddress;
            uint64_t readWritePhysicalPage;   // Dummy page returned on Read/Write
            uint64_t executePhysicalPage;     // Actual page executed by CPU
            size_t pageSize;
            bool isCloaked;
        };

        // Initializes Extended Page Table (EPT) shadow page splitting engine
        bool InitializeEptShadowEngine();

        // Configures Split TLB / Shadow Page for a target kernel memory region
        bool ApplySplitTLB(uint64_t targetVirtualAddress, size_t size);

        // Removes EPT cloaking and restores original page table entries
        bool RemoveSplitTLB(uint64_t targetVirtualAddress);

    }
}
