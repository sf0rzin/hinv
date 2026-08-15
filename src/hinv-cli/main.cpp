#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>

#include "../hinv-core/hinv_byovd.hpp"
#include "../hinv-core/hinv_kmem.hpp"
#include "../hinv-core/hinv_vmm.hpp"
#include "../hinv-core/hinv_cleaner.hpp"
#include "../hinv-core/hinv_mapper.hpp"
#include "../hinv-core/headless/hinv_headless.hpp"

static void PrintUsage() {
    std::cout << "Usage:\n"
              << "  hinv.exe load <driver.sys> [more modules...] --byovd <vulnerable.sys> [--null-drvobj]\n"
              << "  hinv.exe clean <drivername> --byovd <vulnerable.sys>\n"
              << "  hinv.exe headless --byovd <vulnerable.sys> [--script <script.txt>]\n"
              << "  hinv.exe status\n"
              << "\n"
              << "  --null-drvobj   Run DriverEntry with the real DRIVER_OBJECT of \\Driver\\Null\n"
              << "                  instead of a synthetic one. Required for drivers that create\n"
              << "                  devices (e.g. HyperDbg's hyperkd.sys).\n";
}

#include "../hinv-core/hinv_util.hpp"

using hinv::util::ToWstring;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::string command = argv[1];

    // Parse common flags.
    std::wstring byovdPath;
    std::string scriptPath;
    bool nullDrvObj = false;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--byovd" && i + 1 < argc) byovdPath = ToWstring(argv[++i]);
        else if (arg == "--script" && i + 1 < argc) scriptPath = argv[++i];
        else if (arg == "--null-drvobj") nullDrvObj = true;
    }

    if (command == "status") {
        std::cout << "[*] HyperDbg device: " << (hinv::vmm::IsVmmDeviceActive() ? "ready" : "not loaded") << "\n";
        std::cout << "[*] BYOVD backend: " << (byovdPath.empty() ? "not configured" : "configured") << "\n";
        return 0;
    }

    if (command == "headless") {
        hinv::headless::HeadlessConfig config;
        config.byovdDriverPath = byovdPath;
        config.scriptPath = scriptPath;
        return hinv::headless::RunHeadlessSession(config) ? 0 : 1;
    }

    // Commands below require an active BYOVD backend. Unknown commands must
    // bail BEFORE we install/start the vulnerable driver (and with a non-zero
    // exit code, so scripts notice).
    if (command != "load" && command != "clean") {
        PrintUsage();
        return 1;
    }

    if (byovdPath.empty()) {
        std::cerr << "[-] This command requires --byovd <vulnerable.sys>\n";
        return 1;
    }

    hinv::kmem::Trace("cli: backend load begin");
    auto backend = hinv::byovd::LoadVulnerableDriver(byovdPath);
    if (!backend) {
        std::cerr << "[-] Failed to load BYOVD backend\n";
        hinv::kmem::Trace("cli: backend load failed");
        return 1;
    }
    hinv::kmem::Trace("cli: backend ready");

    if (command == "load" && argc >= 3) {
        // Positional arguments are input modules; flags are skipped. Multiple
        // modules are mapped in order within this process so later modules
        // can resolve imports from earlier ones (mapped-module registry).
        std::vector<std::wstring> paths;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if ((arg == "--byovd" || arg == "--script") && i + 1 < argc) { ++i; continue; }
            if (arg == "--null-drvobj") continue;
            if (arg.rfind("--", 0) == 0) {
                // A mistyped flag must never become a module path.
                std::cerr << "[-] Unknown flag: " << arg << "\n";
                return 1;
            }
            paths.push_back(ToWstring(arg));
        }
        if (paths.empty()) {
            std::cerr << "[-] No input files given\n";
            return 1;
        }
        if (paths.size() > 1) {
            std::cout << "[*] Chain-mapping " << paths.size() << " modules in order\n";
            if (nullDrvObj) {
                std::cout << "[!] --null-drvobj with multiple modules: every module WITH an entry point "
                             "shares \\Driver\\Null's object — the last one wins the dispatch table. "
                             "Intended for chains with a single real driver (e.g. hyperkd + companion DLLs).\n";
            }
        }

        for (const auto& driverPath : paths) {
            std::wcout << L"[*] Loading driver via hinv manual mapper: " << driverPath << L"\n";

            auto result = hinv::mapper::MapDriver(backend.get(), driverPath, nullDrvObj);
            if (!result.success) {
                std::wcerr << L"[-] Manual mapping failed for " << driverPath << L"\n";
                std::cerr << "    " << result.error << "\n";
                return 1;
            }

            std::cout << "[+] Mapped at 0x" << std::hex << result.imageBase
                      << ", DriverEntry returned 0x" << result.driverEntryStatus << std::dec << "\n";
        }
        hinv::kmem::Trace("cli: load all modules done");
        return 0;
    }

    if (command == "clean" && argc >= 3) {
        // First positional (non-flag) argument is the driver name — same
        // convention as load, so `clean --byovd x.sys name` works too.
        std::wstring driverName;
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if ((arg == "--byovd" || arg == "--script") && i + 1 < argc) { ++i; continue; }
            if (arg == "--null-drvobj") continue;
            if (arg.rfind("--", 0) == 0) {
                std::cerr << "[-] Unknown flag: " << arg << "\n";
                return 1;
            }
            driverName = ToWstring(arg);
            break;
        }
        if (driverName.empty()) {
            std::cerr << "[-] No driver name given\n";
            return 1;
        }
        uint32_t timestamp = hinv::cleaner::GetDriverFileTimestamp(byovdPath);
        auto result = hinv::cleaner::CleanDriverTraces(backend.get(), driverName, timestamp);
        if (!result.piDdbCache && !result.hashBucketList && !result.wdFilter) {
            std::wcerr << L"[-] Trace cleaning did not find matching entries: " << result.error << L"\n";
            return 1;
        }
        std::wcout << L"[+] Traces sanitized for " << driverName << L"\n";
        return 0;
    }

    PrintUsage();
    return 1; // unreachable for valid commands; keep non-zero for safety
}
