#include <windows.h>
#include <winternl.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#include "../src/hinv-core/hinv_kmem.hpp"
#include "../src/hinv-core/hinv_vmm.hpp"

namespace {

constexpr size_t kPageSize = 0x1000;
constexpr size_t kMaxTransfer = 0x10000;

struct ProcessBasicInformationCompat {
    PVOID Reserved1 = nullptr;
    PVOID PebBaseAddress = nullptr;
    PVOID Reserved2[2]{};
    ULONG_PTR UniqueProcessId = 0;
    PVOID Reserved3 = nullptr;
};

using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

struct TestState {
    int passed = 0;
    int failed = 0;

    void Check(const char* name, bool ok) {
        std::cout << (ok ? "[PASS] " : "[FAIL] ") << name << "\n";
        if (ok) ++passed;
        else ++failed;
    }
};

struct TargetProcess {
    PROCESS_INFORMATION info{};
    LPVOID scratch = nullptr;

    ~TargetProcess() {
        if (scratch && info.hProcess)
            VirtualFreeEx(info.hProcess, scratch, 0, MEM_RELEASE);
        if (info.hProcess) {
            TerminateProcess(info.hProcess, 0);
            WaitForSingleObject(info.hProcess, 5000);
            CloseHandle(info.hProcess);
        }
        if (info.hThread) CloseHandle(info.hThread);
    }
};

bool IsHyperDbgSuccess(uint32_t status) {
    return status == hinv::vmm::DEBUGGER_OPERATION_WAS_SUCCESSFUL;
}

bool ReadMemoryHyperDbg(DWORD pid, uint64_t address,
                        hinv::vmm::ReadMemoryType memoryType,
                        void* out, size_t size) {
    if (!out || size == 0 || size > kMaxTransfer ||
        static_cast<uint64_t>(size) > std::numeric_limits<uint64_t>::max() - address)
        return false;

    std::vector<uint8_t> packet(sizeof(hinv::vmm::DebugerReadMemoryPacket) + size, 0);
    auto* header = reinterpret_cast<hinv::vmm::DebugerReadMemoryPacket*>(packet.data());
    header->Pid = memoryType == hinv::vmm::ReadMemoryType::Physical ? 0 : pid;
    header->Address = address;
    header->Size = static_cast<uint32_t>(size);
    header->GetAddressMode = 0;
    header->AddrMode = hinv::vmm::AddressMode::Mode64;
    header->MemType = memoryType;
    header->ReadType = hinv::vmm::ReadingType::Kernel;

    DWORD bytes = 0;
    const DWORD packetSize = static_cast<DWORD>(packet.size());
    if (!hinv::vmm::SendVmmIoctl(
            hinv::vmm::IOCTL_HYPERDBG_READ_MEMORY,
            packet.data(), packetSize, packet.data(), packetSize, &bytes) ||
        bytes != packetSize || !IsHyperDbgSuccess(header->KernelStatus))
        return false;

    std::memcpy(out, packet.data() + sizeof(*header), size);
    return true;
}

bool EditMemoryHyperDbg(DWORD pid, uint64_t address,
                        const void* data, size_t size) {
    if (!data || (size != 4 && size != 8)) return false;

    const uint32_t byteSize = size == 4 ? 1u : 2u;
    std::vector<uint8_t> packet(sizeof(hinv::vmm::DebugerEditMemoryPacket) + size, 0);
    auto* header = reinterpret_cast<hinv::vmm::DebugerEditMemoryPacket*>(packet.data());
    header->Address = address;
    header->ProcessId = pid;
    header->MemoryType = 0; // virtual
    header->ByteSize = byteSize;
    header->CountOf64Chunks = 1;
    header->FinalStructureSize = static_cast<uint32_t>(packet.size());
    std::memcpy(packet.data() + sizeof(*header), data, size);

    DWORD bytes = 0;
    if (!hinv::vmm::SendVmmIoctl(
            hinv::vmm::IOCTL_HYPERDBG_EDIT_MEMORY,
            packet.data(), static_cast<DWORD>(packet.size()),
            packet.data(), sizeof(*header), &bytes) ||
        bytes != sizeof(*header) || !IsHyperDbgSuccess(header->Result))
        return false;
    return true;
}

bool QueryPeb(HANDLE process, uint64_t& peb) {
    peb = 0;
    auto* ntdll = GetModuleHandleW(L"ntdll.dll");
    NtQueryInformationProcessFn query = nullptr;
    if (ntdll) {
        FARPROC rawQuery = GetProcAddress(ntdll, "NtQueryInformationProcess");
        static_assert(sizeof(query) == sizeof(rawQuery));
        std::memcpy(&query, &rawQuery, sizeof(query));
    }
    if (!query) return false;

    ProcessBasicInformationCompat info{};
    ULONG returned = 0;
    if (query(process, 0, &info, sizeof(info), &returned) < 0 ||
        !info.PebBaseAddress)
        return false;
    peb = reinterpret_cast<uint64_t>(info.PebBaseAddress);
    return true;
}

bool ReadProcessMemoryNative(HANDLE process, uint64_t address,
                             void* out, size_t size) {
    SIZE_T read = 0;
    return ReadProcessMemory(process, reinterpret_cast<const void*>(address),
                             out, size, &read) && read == size;
}

bool WriteProcessMemoryNative(HANDLE process, uint64_t address,
                              const void* data, size_t size) {
    SIZE_T written = 0;
    return WriteProcessMemory(process, reinterpret_cast<void*>(address),
                              data, size, &written) && written == size;
}

bool EnableSeDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &token))
        return false;

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    const bool found = LookupPrivilegeValueW(
        nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid);
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const bool adjusted = found && AdjustTokenPrivileges(
        token, FALSE, &privileges, 0, nullptr, nullptr);
    const bool enabled = adjusted && GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return enabled;
}

bool CreateTarget(TargetProcess& target) {
    std::vector<wchar_t> path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(),
                                            static_cast<DWORD>(path.size()));
    if (!length || length >= path.size()) return false;
    path.resize(length);

    std::wstring command = L"\"" + std::wstring(path.begin(), path.end()) +
                           L"\" --target";
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    if (!CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                        &target.info))
        return false;

    Sleep(250);
    return true;
}

int RunTarget() {
    void* page = VirtualAlloc(nullptr, kPageSize, MEM_RESERVE | MEM_COMMIT,
                              PAGE_READWRITE);
    if (!page) return 2;
    std::memset(page, 0x5A, kPageSize);
    std::cout << "target-ready pid=" << GetCurrentProcessId() << "\n";
    std::cout.flush();
    Sleep(120000);
    VirtualFree(page, 0, MEM_RELEASE);
    return 0;
}

uint64_t FindKernelBase() {
    for (const auto& module : hinv::kmem::EnumKernelModules()) {
        if (hinv::kmem::NormalizeModuleName(module.name) == L"ntoskrnl.exe")
            return module.base;
    }
    return 0;
}

void PrintUsage() {
    std::cout << "Usage: hinv_hyperdbg_api_smoke.exe [--skip-init] [--close-session] [--ept-smoke] [--script-smoke]\n"
              << "       hinv_hyperdbg_api_smoke.exe --target\n"
              << "\n"
              << "--skip-init reuses an already initialized VMM session.\n"
              << "--close-session explicitly closes the caller's VMM handle.\n"
              << "--ept-smoke enables the opt-in EPT monitor/inline-hook lifecycle tests.\n"
              << "--script-smoke enables the optional v0.23 script-engine compile/execute test.\n";
}

} // namespace

int main(int argc, char** argv) {
    bool skipInit = false;
    bool closeSession = false;
    bool eptSmoke = false;
    bool scriptSmoke = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--target") == 0) return RunTarget();
        if (std::strcmp(argv[i], "--skip-init") == 0) {
            skipInit = true;
            continue;
        }
        if (std::strcmp(argv[i], "--close-session") == 0) {
            closeSession = true;
            continue;
        }
        if (std::strcmp(argv[i], "--ept-smoke") == 0) {
            eptSmoke = true;
            continue;
        }
        if (std::strcmp(argv[i], "--script-smoke") == 0) {
            scriptSmoke = true;
            continue;
        }
        PrintUsage();
        return 2;
    }

    TestState state;
    const auto os = hinv::kmem::GetOsVersion();
    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);
    std::cout << "[INFO] Windows build=" << os.build
              << " processors=" << systemInfo.dwNumberOfProcessors
              << " pid=" << GetCurrentProcessId() << "\n";

    state.Check("Enable SeDebugPrivilege", EnableSeDebugPrivilege());
    state.Check("HyperDbg device object is present", hinv::vmm::IsVmmDeviceActive());
    if (state.failed) return 1;

    bool vmmReady = skipInit;
    if (skipInit) {
        std::cout << "[INFO] Reusing existing VMM session\n";
    } else {
        vmmReady = hinv::vmm::InitializeVmm();
        state.Check("InitializeVmm", vmmReady);
    }
    if (!vmmReady) return 1;

    if (scriptSmoke) {
        std::vector<uint8_t> compiledScript;
        uint32_t scriptPointer = 0;
        const bool compiled = hinv::vmm::CompileUserScriptHyperDbg(
            "formats(1 + 2);", compiledScript, scriptPointer);
        state.Check("Compile script through HyperDbg v0.23 runtime",
                    compiled && scriptPointer != 0 &&
                    compiledScript.size() == static_cast<size_t>(scriptPointer) * 24);
    }

    std::vector<uint64_t> tscValues;
    state.Check("Read IA32_TSC MSR on all active cores",
                hinv::vmm::ReadMsrHyperDbg(
                    0x10, hinv::vmm::sdk::kAllCores, tscValues) &&
                !tscValues.empty());

    constexpr uint64_t kSmokeEventTag = 0x48494E565F455654ULL;
    hinv::vmm::sdk::GeneralEventDetail event{};
    event.CoreId = hinv::vmm::sdk::kAllCores;
    event.ProcessId = hinv::vmm::sdk::kAllProcesses;
    event.EventStage = hinv::vmm::sdk::EventStage::Pre;
    event.Tag = kSmokeEventTag;
    event.EventType = hinv::vmm::sdk::EventType::CpuidInstructionExecution;
    const bool eventRegistered = hinv::vmm::RegisterEventHyperDbg(event, {});
    state.Check("Register disabled CPUID event", eventRegistered);

    bool eventEnabled = true;
    const bool eventQueried = eventRegistered &&
        hinv::vmm::ModifyEventHyperDbg(
            kSmokeEventTag, hinv::vmm::sdk::ModifyEventsType::QueryState,
            eventEnabled);
    state.Check("Query disabled event state", eventQueried && !eventEnabled);

    bool ignoredEventState = false;
    state.Check("Clear registered event", eventRegistered &&
                hinv::vmm::ModifyEventHyperDbg(
                    kSmokeEventTag, hinv::vmm::sdk::ModifyEventsType::Clear,
                    ignoredEventState));

    constexpr uint64_t kSmokeActionEventTag = 0x48494E565F414354ULL;
    event = {};
    event.CoreId = hinv::vmm::sdk::kAllCores;
    event.ProcessId = hinv::vmm::sdk::kAllProcesses;
    event.EventStage = hinv::vmm::sdk::EventStage::Pre;
    event.Tag = kSmokeActionEventTag;
    event.EventType = hinv::vmm::sdk::EventType::WrmsrInstructionExecution;
    event.Options.OptionalParam1 = 0x40000000; // reserved MSR probe, no normal traffic
    const bool actionEventRegistered = hinv::vmm::RegisterEventHyperDbg(event, {});
    state.Check("Register WRMSR action event", actionEventRegistered);

    hinv::vmm::sdk::GeneralAction action{};
    action.EventTag = kSmokeActionEventTag;
    action.ActionType = hinv::vmm::sdk::EventActionType::BreakToDebugger;
    const bool actionAdded = actionEventRegistered &&
        hinv::vmm::AddActionToEventHyperDbg(action, {});
    state.Check("Add break action to event", actionAdded);

    bool actionEventEnabled = false;
    const bool actionEventQueried = actionAdded &&
        hinv::vmm::ModifyEventHyperDbg(
            kSmokeActionEventTag, hinv::vmm::sdk::ModifyEventsType::QueryState,
            actionEventEnabled);
    state.Check("Query enabled action event", actionEventQueried && actionEventEnabled);

    bool ignoredActionEventState = false;
    state.Check("Clear action event", actionAdded &&
                hinv::vmm::ModifyEventHyperDbg(
                    kSmokeActionEventTag, hinv::vmm::sdk::ModifyEventsType::Clear,
                    ignoredActionEventState));

    const uint64_t kernelBase = FindKernelBase();
    std::array<uint8_t, 16> kernelHeader{};
    const bool kernelRead = kernelBase != 0 &&
        hinv::vmm::ReadKernelMemoryHyperDbg(
            kernelBase, kernelHeader.data(), kernelHeader.size());
    state.Check("Enumerate ntoskrnl and read kernel MZ header",
                kernelRead &&
                kernelHeader[0] == 'M' && kernelHeader[1] == 'Z');

    auto* localPage = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, kPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    state.Check("VirtualAlloc local scratch page", localPage != nullptr);
    if (!localPage) {
        if (!skipInit || closeSession) (void)hinv::vmm::ShutdownVmm();
        return 1;
    }

    constexpr uint64_t kLocalInitial = 0x1122334455667788ULL;
    constexpr uint64_t kLocalEdited = 0x8877665544332211ULL;
    std::memcpy(localPage, &kLocalInitial, sizeof(kLocalInitial));

    uint64_t localRead = 0;
    state.Check("Read current-process virtual memory",
                ReadMemoryHyperDbg(
                    GetCurrentProcessId(), reinterpret_cast<uint64_t>(localPage),
                    hinv::vmm::ReadMemoryType::Virtual,
                    &localRead, sizeof(localRead)) &&
                localRead == kLocalInitial);

    uint64_t physical = 0;
    const bool translated = hinv::vmm::VirtualToPhysicalHyperDbg(
        reinterpret_cast<uint64_t>(localPage), physical);
    state.Check("VirtualToPhysical on committed scratch page",
                translated && physical != 0);

    hinv::vmm::sdk::ReadPageTableEntriesDetails pageTable{};
    state.Check("Read page-table entries for scratch page",
                hinv::vmm::ReadPageTableEntriesHyperDbg(
                    reinterpret_cast<uint64_t>(localPage),
                    GetCurrentProcessId(), pageTable) &&
                pageTable.PteVirtualAddress != 0);

    uint64_t physicalRead = 0;
    state.Check("Read physical memory returned by VA2PA",
                translated && ReadMemoryHyperDbg(
                    GetCurrentProcessId(), physical,
                    hinv::vmm::ReadMemoryType::Physical,
                    &physicalRead, sizeof(physicalRead)) &&
                physicalRead == kLocalInitial);

    const bool localEdit = EditMemoryHyperDbg(
        GetCurrentProcessId(), reinterpret_cast<uint64_t>(localPage),
        &kLocalEdited, sizeof(kLocalEdited));
    uint64_t localAfterEdit = 0;
    std::memcpy(&localAfterEdit, localPage, sizeof(localAfterEdit));
    state.Check("Edit current-process virtual scratch with readback",
                localEdit && localAfterEdit == kLocalEdited);

    // Restore the local scratch value before releasing the page. This still
    // exercises the same verified edit path without touching kernel memory.
    (void)EditMemoryHyperDbg(
        GetCurrentProcessId(), reinterpret_cast<uint64_t>(localPage),
        &kLocalInitial, sizeof(kLocalInitial));

    std::vector<uint64_t> searchResults;
    const bool searchOk = hinv::vmm::SearchMemoryHyperDbg(
        reinterpret_cast<uint64_t>(localPage), kPageSize, GetCurrentProcessId(),
        hinv::vmm::sdk::SearchMemoryType::Virtual,
        hinv::vmm::sdk::SearchMemoryByteSize::Qword,
        { kLocalInitial }, searchResults);
    bool foundLocalScratch = false;
    for (const uint64_t result : searchResults) {
        if (result == reinterpret_cast<uint64_t>(localPage)) {
            foundLocalScratch = true;
            break;
        }
    }
    state.Check("Search current-process virtual scratch", searchOk && foundLocalScratch);

    if (eptSmoke) {
        constexpr uint64_t kSmokeEptEventTag = 0x48494E565F455054ULL;
        hinv::vmm::sdk::GeneralEventDetail eptEvent{};
        eptEvent.CoreId = hinv::vmm::sdk::kAllCores;
        eptEvent.ProcessId = GetCurrentProcessId();
        eptEvent.EventStage = hinv::vmm::sdk::EventStage::Pre;
        eptEvent.Tag = kSmokeEptEventTag;
        eptEvent.EventType = hinv::vmm::sdk::EventType::HiddenHookRead;
        eptEvent.Options.OptionalParam1 = reinterpret_cast<uint64_t>(localPage);
        eptEvent.Options.OptionalParam2 =
            reinterpret_cast<uint64_t>(localPage) + kPageSize - 1;
        eptEvent.Options.OptionalParam3 = 0; // virtual-memory monitor
        const bool eptRegistered = hinv::vmm::RegisterEventHyperDbg(eptEvent, {});
        state.Check("Register opt-in EPT read monitor", eptRegistered);

        hinv::vmm::sdk::GeneralAction eptAction{};
        eptAction.EventTag = kSmokeEptEventTag;
        eptAction.ActionType = hinv::vmm::sdk::EventActionType::BreakToDebugger;
        const bool eptActionAdded = eptRegistered &&
            hinv::vmm::AddActionToEventHyperDbg(eptAction, {});
        state.Check("Add action to opt-in EPT monitor", eptActionAdded);

        bool eptEnabled = false;
        const bool eptQueried = eptActionAdded &&
            hinv::vmm::ModifyEventHyperDbg(
                kSmokeEptEventTag, hinv::vmm::sdk::ModifyEventsType::QueryState,
                eptEnabled);
        state.Check("Query enabled EPT monitor", eptQueried && eptEnabled);

        bool ignoredEptState = false;
        state.Check("Clear opt-in EPT monitor", eptRegistered &&
                    hinv::vmm::ModifyEventHyperDbg(
                        kSmokeEptEventTag, hinv::vmm::sdk::ModifyEventsType::Clear,
                        ignoredEptState));

        auto* detourPage = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, kPageSize, MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE));
        state.Check("VirtualAlloc executable detour page", detourPage != nullptr);
        bool detourCleared = false;
        if (detourPage) {
            std::memset(detourPage, 0x90, kPageSize);
            detourPage[0] = 0xC3; // ret; the page is never executed by the smoke.

            constexpr uint64_t kSmokeDetourEventTag = 0x48494E565F445452ULL;
            hinv::vmm::sdk::GeneralEventDetail detourEvent{};
            detourEvent.CoreId = hinv::vmm::sdk::kAllCores;
            detourEvent.ProcessId = GetCurrentProcessId();
            detourEvent.EventStage = hinv::vmm::sdk::EventStage::Pre;
            detourEvent.Tag = kSmokeDetourEventTag;
            detourEvent.EventType =
                hinv::vmm::sdk::EventType::HiddenHookExecuteDetours;
            detourEvent.Options.OptionalParam1 =
                reinterpret_cast<uint64_t>(detourPage);
            const bool detourRegistered =
                hinv::vmm::RegisterEventHyperDbg(detourEvent, {});
            state.Check("Register opt-in EPT execute detour", detourRegistered);

            hinv::vmm::sdk::GeneralAction detourAction{};
            detourAction.EventTag = kSmokeDetourEventTag;
            detourAction.ActionType =
                hinv::vmm::sdk::EventActionType::BreakToDebugger;
            const bool detourActionAdded = detourRegistered &&
                hinv::vmm::AddActionToEventHyperDbg(detourAction, {});
            state.Check("Add action to opt-in EPT execute detour",
                        detourActionAdded);

            bool detourEnabled = false;
            const bool detourQueried = detourActionAdded &&
                hinv::vmm::ModifyEventHyperDbg(
                    kSmokeDetourEventTag,
                    hinv::vmm::sdk::ModifyEventsType::QueryState,
                    detourEnabled);
            state.Check("Query enabled EPT execute detour",
                        detourQueried && detourEnabled);

            bool ignoredDetourState = false;
            detourCleared = detourRegistered &&
                hinv::vmm::ModifyEventHyperDbg(
                    kSmokeDetourEventTag,
                    hinv::vmm::sdk::ModifyEventsType::Clear,
                    ignoredDetourState);
            state.Check("Clear opt-in EPT execute detour", detourCleared);
            if (detourCleared)
                VirtualFree(detourPage, 0, MEM_RELEASE);
            else
                std::cerr << "[WARN] Detour page retained because event cleanup failed\n";
        }
    }

    TargetProcess target;
    state.Check("Create Windows API target process", CreateTarget(target));
    if (target.info.hProcess) {
        const DWORD targetPid = target.info.dwProcessId;
        target.scratch = VirtualAllocEx(target.info.hProcess, nullptr, kPageSize,
                                        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        constexpr uint64_t kRemoteInitial = 0xAABBCCDDEEFF0011ULL;
        constexpr uint64_t kRemoteEdited = 0x1100FFEEDDCCBBAAULL;
        const bool wrote = target.scratch && WriteProcessMemoryNative(
            target.info.hProcess, reinterpret_cast<uint64_t>(target.scratch),
            &kRemoteInitial, sizeof(kRemoteInitial));

        MEMORY_BASIC_INFORMATION memoryInfo{};
        const bool queried = target.scratch && VirtualQueryEx(
            target.info.hProcess, target.scratch, &memoryInfo,
            sizeof(memoryInfo)) == sizeof(memoryInfo);
        state.Check("VirtualAllocEx/WriteProcessMemory/VirtualQueryEx",
                    wrote && queried && memoryInfo.State == MEM_COMMIT);

        uint64_t nativeRemote = 0;
        state.Check("ReadProcessMemory baseline", wrote &&
                    ReadProcessMemoryNative(
                        target.info.hProcess,
                        reinterpret_cast<uint64_t>(target.scratch),
                        &nativeRemote, sizeof(nativeRemote)) &&
                    nativeRemote == kRemoteInitial);

        uint64_t peb = 0;
        uint64_t imageBaseNative = 0;
        const bool pebOk = QueryPeb(target.info.hProcess, peb) &&
            ReadProcessMemoryNative(target.info.hProcess, peb + 0x10,
                                    &imageBaseNative, sizeof(imageBaseNative));
        state.Check("NtQueryInformationProcess and PEB image base", pebOk &&
                    imageBaseNative != 0);

        uint64_t remoteRead = 0;
        state.Check("Structured HyperDbg cross-process read", wrote &&
                    ReadMemoryHyperDbg(
                        targetPid, reinterpret_cast<uint64_t>(target.scratch),
                        hinv::vmm::ReadMemoryType::Virtual,
                        &remoteRead, sizeof(remoteRead)) &&
                    remoteRead == kRemoteInitial);

        uint64_t imageBaseHyperDbg = 0;
        const bool hyperDbgPebRead = pebOk && ReadMemoryHyperDbg(
            targetPid, peb + 0x10, hinv::vmm::ReadMemoryType::Virtual,
            &imageBaseHyperDbg, sizeof(imageBaseHyperDbg));
        state.Check("Structured HyperDbg PEB read", hyperDbgPebRead &&
                    imageBaseHyperDbg == imageBaseNative);

        const bool remoteEdit = wrote && EditMemoryHyperDbg(
            targetPid, reinterpret_cast<uint64_t>(target.scratch),
            &kRemoteEdited, sizeof(kRemoteEdited));
        uint64_t remoteAfterEdit = 0;
        const bool remoteReadback = remoteEdit && ReadProcessMemoryNative(
            target.info.hProcess, reinterpret_cast<uint64_t>(target.scratch),
            &remoteAfterEdit, sizeof(remoteAfterEdit));
        state.Check("Structured HyperDbg cross-process edit", remoteReadback &&
                    remoteAfterEdit == kRemoteEdited);

        (void)EditMemoryHyperDbg(
            targetPid, reinterpret_cast<uint64_t>(target.scratch),
            &kRemoteInitial, sizeof(kRemoteInitial));

        uint64_t processToken = 0;
        const bool attached = hinv::vmm::AttachProcessHyperDbg(
            targetPid, processToken);
        state.Check("Attach to target process", attached && processToken != 0);
        bool commandPaused = false;
        bool commandContinued = false;
        bool scriptExecuted = false;
        uint64_t scriptValue = 0;
        if (attached) {
            std::vector<uint8_t> commandResponse;
            commandPaused = hinv::vmm::SendUserDebuggerCommandHyperDbg(
                processToken, 0,
                hinv::vmm::sdk::UserDebuggerCommandAction::Pause,
                {}, false, false, 0, 0, 0, 0, commandResponse);
            if (commandPaused && scriptSmoke) {
                scriptExecuted = hinv::vmm::ExecuteTextUserScriptHyperDbg(
                    processToken, 0, "formats(1 + 2);", true, &scriptValue);
            }
            commandContinued = commandPaused &&
                hinv::vmm::ContinueProcessHyperDbg(processToken);
        }
        state.Check("User debugger pause command", attached && commandPaused);
        if (scriptSmoke) {
            state.Check("Execute compiled user script",
                        attached && scriptExecuted && scriptValue == 3);
        }
        state.Check("Continue attached process", attached && commandContinued);
        bool detached = false;
        if (attached) {
            Sleep(500);
            detached = hinv::vmm::DetachProcessHyperDbg(targetPid, processToken);
        }
        state.Check("Detach from target process", attached && detached);
    }

    VirtualFree(localPage, 0, MEM_RELEASE);
    if (!skipInit || closeSession) {
        state.Check("ShutdownVmm", hinv::vmm::ShutdownVmm());
    } else {
        std::cout << "[PASS] Shared VMM session left open\n";
        ++state.passed;
    }
    std::cout << "[INFO] passed=" << state.passed
              << " failed=" << state.failed << "\n";
    return state.failed == 0 ? 0 : 1;
}
