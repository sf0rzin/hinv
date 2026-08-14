#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>

#include "../hinv-core/hinv_byovd.hpp"
#include "../hinv-core/hinv_hijack.hpp"
#include "../hinv-core/hinv_vmm.hpp"
#include "../hinv-core/hinv_ept_shadow.hpp"
#include "../hinv-core/hinv_cleaner.hpp"
#include "../hinv-core/hinv_mapper.hpp"
#include "../hinv-core/headless/hinv_headless.hpp"

static void PrintUsage() {
    std::cout << "Usage:\n"
              << "  hinv.exe load <driver.sys> [more modules...] --byovd <vulnerable.sys>\n"
              << "  hinv.exe clean <drivername> --byovd <vulnerable.sys>\n"
              << "  hinv.exe cloak <hex_address> <size>\n"
              << "  hinv.exe headless --byovd <vulnerable.sys> [--script <script.txt>]\n"
              << "  hinv.exe hypercmd <command>\n"
              << "  hinv.exe status\n\n";
}

static std::wstring ToWstring(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::string command = argv[1];

    // Parse common flags.
    std::wstring byovdPath;
    std::string scriptPath;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--byovd" && i + 1 < argc) byovdPath = ToWstring(argv[++i]);
        else if (arg == "--script" && i + 1 < argc) scriptPath = argv[++i];
    }

    if (command == "status") {
        std::cout << "[*] HyperDbg device: " << (hinv::vmm::IsVmmDeviceActive() ? "ready" : "not loaded") << "\n";
        std::cout << "[*] BYOVD backend: " << (byovdPath.empty() ? "not configured" : "configured") << "\n";
        return 0;
    }

    if (command == "hypercmd" && argc >= 3) {
        std::string cmd = argv[2];
        for (int i = 3; i < argc; ++i) cmd += std::string(" ") + argv[i];
        if (!hinv::vmm::SendVmmCommand(cmd)) {
            std::cerr << "[-] HyperDbg command failed\n";
            return 1;
        }
        std::cout << "[+] HyperDbg command sent\n";
        return 0;
    }

    if (command == "cloak" && argc >= 4) {
        uint64_t addr = std::strtoull(argv[2], nullptr, 0);
        size_t size = std::strtoull(argv[3], nullptr, 0);
        if (!hinv::ept::ApplySplitTLB(addr, size)) {
            std::cerr << "[-] EPT cloak failed\n";
            return 1;
        }
        std::cout << "[+] EPT cloak applied\n";
        return 0;
    }

    if (command == "headless") {
        hinv::headless::HeadlessConfig config;
        config.byovdDriverPath = byovdPath;
        config.scriptPath = scriptPath;
        hinv::headless::RunHeadlessSession(config);
        return 0;
    }

    // Commands below require an active BYOVD backend.
    if (byovdPath.empty()) {
        std::cerr << "[-] This command requires --byovd <vulnerable.sys>\n";
        return 1;
    }

    auto backend = hinv::byovd::LoadVulnerableDriver(byovdPath);
    if (!backend) {
        std::cerr << "[-] Failed to load BYOVD backend\n";
        return 1;
    }

    if (command == "load" && argc >= 3) {
        // Positional arguments are input modules; flags are skipped. Multiple
        // modules are mapped in order within this process so later modules
        // can resolve imports from earlier ones (mapped-module registry).
        std::vector<std::wstring> paths;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if ((arg == "--byovd" || arg == "--script") && i + 1 < argc) { ++i; continue; }
            paths.push_back(ToWstring(arg));
        }
        if (paths.empty()) {
            std::cerr << "[-] No input files given\n";
            return 1;
        }
        if (paths.size() > 1) {
            std::cout << "[*] Chain-mapping " << paths.size() << " modules in order\n";
        }

        for (const auto& driverPath : paths) {
            std::wcout << L"[*] Loading driver via hinv manual mapper: " << driverPath << L"\n";

            auto result = hinv::mapper::MapDriver(backend.get(), driverPath);
            if (!result.success) {
                std::wcerr << L"[-] Manual mapping failed for " << driverPath << L"\n";
                std::cerr << "    " << result.error << "\n";
                return 1;
            }

            std::cout << "[+] Mapped at 0x" << std::hex << result.imageBase
                      << ", DriverEntry returned 0x" << result.driverEntryStatus << std::dec << "\n";
        }
        return 0;
    }

    if (command == "clean" && argc >= 3) {
        std::wstring driverName = ToWstring(argv[2]);
        auto result = hinv::cleaner::CleanDriverTraces(backend.get(), driverName);
        if (!result.mmUnloadedDrivers && !result.piDdbCache) {
            std::wcerr << L"[-] Trace cleaning did not find matching entries: " << result.error << L"\n";
            return 1;
        }
        std::wcout << L"[+] Traces sanitized for " << driverName << L"\n";
        return 0;
    }

    PrintUsage();
    return 0;
}
