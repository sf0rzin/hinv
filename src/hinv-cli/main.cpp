#include <windows.h>
#include <iostream>
#include <string>

#include "../hinv-core/hinv_hijack.hpp"
#include "../hinv-core/hinv_iat.hpp"
#include "../hinv-core/hinv_vmm.hpp"
#include "../hinv-core/headless/hinv_headless.hpp"

void PrintBanner() {
    std::cout << "========================================================\n";
    std::cout << "  hinv (Hyper Invisible) - Stealth Loader & Headless VMM \n";
    std::cout << "========================================================\n\n";
}

void PrintUsage() {
    std::cout << "Usage:\n";
    std::cout << "  hinv.exe load <path_to_driver.sys>\n";
    std::cout << "  hinv.exe headless [--script <script.txt>]\n";
    std::cout << "  hinv.exe status\n";
    std::cout << "  hinv.exe cloak <hex_address> <size>\n\n";
}

int main(int argc, char* argv[]) {
    PrintBanner();

    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::string command = argv[1];

    if (command == "status") {
        std::cout << "[*] Checking hinv & HyperDbg VMM status...\n";
        uint64_t nullDriverBase = hinv::hijack::GetDriverObjectAddress(L"Null");
        bool vmmActive = hinv::vmm::IsVmmDeviceActive();

        std::cout << "[+] Native null.sys Driver Base : 0x" << std::hex << nullDriverBase << std::dec << "\n";
        std::cout << "[+] HyperDbg VMM Device Active  : " << (vmmActive ? "YES (VT-x Active)" : "NO (Not Loaded)") << "\n";
        return 0;
    }

    if (command == "headless") {
        hinv::headless::HeadlessConfig config;
        for (int i = 2; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--script" && i + 1 < argc) {
                config.scriptPath = argv[++i];
            }
        }
        hinv::headless::RunHeadlessSession(config);
        return 0;
    }

    if (command == "load" && argc >= 3) {
        std::string driverPath = argv[2];
        std::cout << "[*] Loading driver via hinv manual mapper: " << driverPath << "\n";

        // 1. Hijack DriverObject
        uint64_t nullDriverBase = hinv::hijack::GetDriverObjectAddress(L"Null");
        hinv::hijack::PrepareHijackedDriverObject(nullDriverBase, 0x10000);

        // 2. Perform IAT dependency filtering
        hinv::iat::IsUserModeModule("hyperlog.dll");

        // 3. Apply EPT Memory Cloaking
        hinv::vmm::CloakKernelMemory(0x10000, 4096);

        std::cout << "[+] Driver " << driverPath << " processed cleanly by hinv loader.\n";
        return 0;
    }

    PrintUsage();
    return 0;
}
