#include <windows.h>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "../hinv-core/hinv_byovd.hpp"
#include "../hinv-core/hinv_kmem.hpp"
#include "../hinv-core/hinv_vmm.hpp"
#include "../hinv-core/hinv_maintenance.hpp"
#include "../hinv-core/hinv_mapper.hpp"
#include "../hinv-core/headless/hinv_headless.hpp"

static void PrintUsage() {
    std::cout << "Usage:\n"
              << "  hinv.exe load <driver.sys> [more modules...] --byovd <vulnerable.sys> [--null-drvobj]\n"
              << "  hinv.exe process-traces <drivername> --byovd <vulnerable.sys>\n"
              << "  hinv.exe headless --byovd <vulnerable.sys> [--script <script.txt>]\n"
              << "  hinv.exe status\n"
              << "\n"
              << "  --null-drvobj   Use a real DRIVER_OBJECT created via IoCreateDriver\n"
              << "                  instead of a synthetic one. The legacy flag name does not\n"
              << "                  modify \\Driver\\Null; useful for drivers creating devices.\n";
}

static int RunWideMain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    const std::wstring command = argv[1];

    // Parse and validate flags before any privileged operation.
    std::wstring byovdPath;
    std::filesystem::path scriptPath;
    bool nullDrvObj = false;
    bool parseError = false;
    for (int i = 2; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--byovd") {
            if (command == L"status" || i + 1 >= argc ||
                std::wstring(argv[i + 1]).rfind(L"--", 0) == 0) {
                parseError = true;
                break;
            }
            byovdPath = argv[++i];
        } else if (arg == L"--script") {
            if (command != L"headless" || i + 1 >= argc ||
                std::wstring(argv[i + 1]).rfind(L"--", 0) == 0) {
                parseError = true;
                break;
            }
            scriptPath = argv[++i];
        } else if (arg == L"--null-drvobj") {
            if (command != L"load") {
                parseError = true;
                break;
            }
            nullDrvObj = true;
        } else if (arg.rfind(L"--", 0) == 0) {
            std::wcerr << L"[-] Unknown flag: " << arg << L"\n";
            parseError = true;
            break;
        }
    }
    if (parseError) {
        PrintUsage();
        return 1;
    }

    if (command == L"status") {
        if (argc != 2) {
            PrintUsage();
            return 1;
        }
        std::cout << "[*] HyperDbg device: " << (hinv::vmm::IsVmmDeviceActive() ? "ready" : "not loaded") << "\n";
        std::cout << "[*] BYOVD backend: not configured\n";
        return 0;
    }

    if (command == L"headless") {
        for (int i = 2; i < argc; ++i) {
            const std::wstring arg = argv[i];
            if (arg == L"--byovd" || arg == L"--script") {
                ++i;
                continue;
            }
            std::wcerr << L"[-] Headless does not accept positional arguments: " << arg << L"\n";
            return 1;
        }
        hinv::headless::HeadlessConfig config;
        config.byovdDriverPath = byovdPath;
        config.scriptPath = scriptPath;
        return hinv::headless::RunHeadlessSession(config) ? 0 : 1;
    }

    // Commands below require an active BYOVD backend. Unknown commands must
    // bail BEFORE we install/start the vulnerable driver (and with a non-zero
    // exit code, so scripts notice).
    if (command != L"load" && command != L"process-traces") {
        PrintUsage();
        return 1;
    }

    if (byovdPath.empty()) {
        std::cerr << "[-] This command requires --byovd <vulnerable.sys>\n";
        return 1;
    }

    std::vector<std::wstring> paths;
    std::wstring driverName;
    for (int i = 2; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--byovd") {
            ++i;
            continue;
        }
        if (arg == L"--null-drvobj") continue;
        if (!arg.empty() && arg[0] == L'-') {
            std::wcerr << L"[-] Unknown flag: " << arg << L"\n";
            return 1;
        }
        if (command == L"load") {
            paths.push_back(arg);
        } else if (driverName.empty()) {
            driverName = arg;
        } else {
            std::cerr << "[-] Too many positional arguments for process-traces\n";
            return 1;
        }
    }
    if (command == L"load" && paths.empty()) {
        std::cerr << "[-] No input files given\n";
        return 1;
    }
    if (command == L"process-traces" && driverName.empty()) {
        std::cerr << "[-] No driver name given\n";
        return 1;
    }

    std::vector<std::vector<uint8_t>> moduleBytes;
    if (command == L"load") {
        moduleBytes.reserve(paths.size());
        for (const auto& path : paths) {
            std::vector<uint8_t> bytes;
            std::string validationError;
            if (!hinv::mapper::ReadDriverFileBytes(path, bytes) ||
                !hinv::mapper::ValidateDriverImageBytes(bytes, &validationError)) {
                std::wcerr << L"[-] Module preflight failed for " << path << L"\n";
                std::cerr << "    " << validationError << "\n";
                return 1;
            }
            moduleBytes.push_back(std::move(bytes));
        }
    }

    uint32_t driverTimestamp = 0;
    if (command == L"process-traces") {
        driverTimestamp = hinv::maintenance::GetDriverFileTimestamp(byovdPath);
        if (driverTimestamp == 0) {
            std::wcerr << L"[-] BYOVD preflight failed: invalid or unreadable PE file\n";
            return 1;
        }
    }

    hinv::kmem::Trace("cli: backend load begin");
    auto backend = hinv::byovd::LoadVulnerableDriver(byovdPath);
    if (!backend) {
        std::cerr << "[-] Failed to load BYOVD backend\n";
        hinv::kmem::Trace("cli: backend load failed");
        return 1;
    }
    hinv::kmem::Trace("cli: backend ready");
    auto shutdownBackend = [&]() {
        const bool ok = backend->Shutdown();
        if (ok) backend.reset();
        return ok;
    };

    if (command == L"load") {
        // Positional arguments are input modules; flags are skipped. Multiple
        // modules are mapped in order within this process so later modules
        // can resolve imports from earlier ones (mapped-module registry).
        if (paths.size() > 1) {
            std::cout << "[*] Chain-mapping " << paths.size() << " modules in order\n";
            if (nullDrvObj) {
                std::cout << "[!] --null-drvobj with multiple modules: every module with an entry point "
                             "gets its own IoCreateDriver object. Use it only for the real driver in the chain.\n";
            }
        }

        for (size_t index = 0; index < paths.size(); ++index) {
            const auto& driverPath = paths[index];
            std::wcout << L"[*] Loading driver via hinv manual mapper: " << driverPath << L"\n";

            auto result = hinv::mapper::MapDriverBytes(
                backend.get(), moduleBytes[index], nullDrvObj);
            if (!result.success) {
                std::wcerr << L"[-] Manual mapping failed for " << driverPath << L"\n";
                std::cerr << "    " << result.error << "\n";
                shutdownBackend();
                return 1;
            }

            const size_t slash = driverPath.find_last_of(L"\\/");
            const std::wstring fileName = slash == std::wstring::npos
                ? driverPath : driverPath.substr(slash + 1);
            hinv::kmem::RegisterMappedModule(fileName, result.imageBase, result.imageSize);

            std::cout << "[+] Mapped at 0x" << std::hex << result.imageBase
                      << ", DriverEntry returned 0x" << result.driverEntryStatus << std::dec << "\n";
        }
        hinv::kmem::Trace("cli: load all modules done");
        if (!shutdownBackend()) {
            std::cerr << "[-] Backend teardown failed; refusing success\n";
            return 1;
        }
        return 0;
    }

    if (command == L"process-traces") {
        // First positional (non-flag) argument is the driver name — same
        // convention as load, so `process-traces --byovd x.sys name` works too.
        auto result = hinv::maintenance::ProcessDriverTraces(backend.get(), driverName, driverTimestamp);
        if (!result.piDdbCache && !result.hashBucketList && !result.wdFilter) {
            std::wcerr << L"[-] Trace processing did not find matching entries: " << result.error << L"\n";
            shutdownBackend();
            return 1;
        }
        if (!result.complete) {
            std::wcerr << L"[-] Trace processing was partial: " << result.error << L"\n";
            shutdownBackend();
            return 1;
        }
        std::wcout << L"[+] Traces sanitized for " << driverName << L"\n";
        if (!shutdownBackend()) {
            std::cerr << "[-] Backend teardown failed; refusing success\n";
            return 1;
        }
        return 0;
    }

    PrintUsage();
    return 1; // unreachable for valid commands; keep non-zero for safety
}

int main() {
    // Keep the normal console entry point (important for MinGW builds without
    // -municode), but obtain argv from the UTF-16 command line. Resolve
    // CommandLineToArgvW dynamically so no Shell32 linker change is required.
    HMODULE shell32 = LoadLibraryW(L"shell32.dll");
    if (!shell32) {
        std::cerr << "[-] Cannot load shell32.dll\n";
        return 1;
    }

    using ParseCommandLineFn = LPWSTR* (WINAPI*)(LPCWSTR, int*);
    FARPROC rawParser = GetProcAddress(shell32, "CommandLineToArgvW");
    ParseCommandLineFn parseCommandLine = nullptr;
    static_assert(sizeof(parseCommandLine) == sizeof(rawParser));
    std::memcpy(&parseCommandLine, &rawParser, sizeof(parseCommandLine));
    if (!parseCommandLine) {
        FreeLibrary(shell32);
        std::cerr << "[-] Cannot resolve CommandLineToArgvW\n";
        return 1;
    }

    int argc = 0;
    LPWSTR* argv = parseCommandLine(GetCommandLineW(), &argc);
    if (!argv) {
        FreeLibrary(shell32);
        std::cerr << "[-] Cannot parse the process command line\n";
        return 1;
    }

    const int result = RunWideMain(argc, argv);
    LocalFree(argv);
    FreeLibrary(shell32);
    return result;
}
