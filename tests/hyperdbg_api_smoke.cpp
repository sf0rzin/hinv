#include <windows.h>
#include <winternl.h>
#include <intrin.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <cstdlib>
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
    volatile LONG64 heartbeat = 0;
    const ULONGLONG deadline = GetTickCount64() + 120000;
    while (GetTickCount64() < deadline) {
        InterlockedIncrement64(&heartbeat);
        YieldProcessor();
    }
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

uint64_t FindKernelExportAddress(uint64_t kernelBase, const char* name) {
    if (kernelBase == 0 || !name) return 0;

    wchar_t systemDirectory[MAX_PATH]{};
    const UINT length = GetSystemDirectoryW(
        systemDirectory, static_cast<UINT>(std::size(systemDirectory)));
    if (length == 0 || length >= std::size(systemDirectory)) return 0;

    std::wstring path(systemDirectory, length);
    path += L"\\ntoskrnl.exe";
    HMODULE image = LoadLibraryExW(path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!image) return 0;

    const FARPROC exportAddress = GetProcAddress(image, name);
    const uint64_t imageBase = reinterpret_cast<uint64_t>(image);
    const uint64_t localAddress = reinterpret_cast<uint64_t>(exportAddress);
    const uint64_t rva = exportAddress && localAddress >= imageBase
        ? localAddress - imageBase : 0;
    FreeLibrary(image);
    return rva == 0 ? 0 : kernelBase + rva;
}

bool UnsafeHyperDbgTriggersEnabled() {
    const char* value = std::getenv("HINV_ENABLE_UNSAFE_HYPERDBG_TRIGGERS");
    return value && std::strcmp(value, "1") == 0;
}

void PrintUsage() {
    std::cout << "Usage: hinv_hyperdbg_api_smoke.exe [--skip-init] [--close-session] [--ept-smoke] [--ept-trigger-smoke] [--script-smoke] [--custom-trigger-smoke] [--msr-write-smoke]\n"
              << "       hinv_hyperdbg_api_smoke.exe --target\n"
              << "\n"
              << "--skip-init reuses an already initialized VMM session.\n"
              << "--close-session explicitly closes the caller's VMM handle.\n"
              << "--ept-smoke enables the opt-in EPT monitor/inline-hook lifecycle tests.\n"
              << "--ept-trigger-smoke performs a real EPT read trigger; execute is unsafe-gated.\n"
              << "--script-smoke enables the optional v0.23 script-engine compile/execute test.\n"
              << "--custom-trigger-smoke registers a custom action; execution is unsafe-gated.\n"
              << "--msr-write-smoke enables the gated same-value MSR write/restore test.\n"
              << "HINV_ENABLE_UNSAFE_HYPERDBG_TRIGGERS=1 is required for real execute/custom triggers.\n";
}

} // namespace

int main(int argc, char** argv) {
    bool skipInit = false;
    bool closeSession = false;
    bool eptSmoke = false;
    bool eptTriggerSmoke = false;
    bool scriptSmoke = false;
    bool customTriggerSmoke = false;
    bool msrWriteSmoke = false;
    std::cout.setf(std::ios::unitbuf);
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
        if (std::strcmp(argv[i], "--ept-trigger-smoke") == 0) {
            eptSmoke = true;
            eptTriggerSmoke = true;
            scriptSmoke = true;
            continue;
        }
        if (std::strcmp(argv[i], "--script-smoke") == 0) {
            scriptSmoke = true;
            continue;
        }
        if (std::strcmp(argv[i], "--custom-trigger-smoke") == 0) {
            scriptSmoke = true;
            customTriggerSmoke = true;
            continue;
        }
        if (std::strcmp(argv[i], "--msr-write-smoke") == 0) {
            msrWriteSmoke = true;
            continue;
        }
        PrintUsage();
        return 2;
    }
    const bool unsafeTriggersEnabled = UnsafeHyperDbgTriggersEnabled();

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

    if (msrWriteSmoke) {
        std::vector<uint64_t> restoredTsc;
        const bool wroteSameValue = !tscValues.empty() &&
            hinv::vmm::WriteMsrHyperDbg(0x10, tscValues[0], 0);
        const bool restored = wroteSameValue &&
            hinv::vmm::ReadMsrHyperDbg(0x10, 0, restoredTsc);
        state.Check("Write and restore IA32_TSC on core 0",
                    restored && restoredTsc.size() == 1);
    }

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

    bool ignoredDisabledState = false;
    const bool actionEventDisabled = actionEventRegistered &&
        hinv::vmm::ModifyEventHyperDbg(
            kSmokeActionEventTag, hinv::vmm::sdk::ModifyEventsType::Disable,
            ignoredDisabledState);
    bool actionEventDisabledQueried = true;
    const bool actionEventDisableQuery = actionEventDisabled &&
        hinv::vmm::ModifyEventHyperDbg(
            kSmokeActionEventTag, hinv::vmm::sdk::ModifyEventsType::QueryState,
            actionEventDisabledQueried);
    state.Check("Disable and query action event",
                actionEventDisableQuery && !actionEventDisabledQueried);

    bool ignoredEnabledState = false;
    const bool actionEventEnabledAgain = actionEventDisabled &&
        hinv::vmm::ModifyEventHyperDbg(
            kSmokeActionEventTag, hinv::vmm::sdk::ModifyEventsType::Enable,
            ignoredEnabledState);
    bool actionEventReenabledQueried = false;
    const bool actionEventEnableQuery = actionEventEnabledAgain &&
        hinv::vmm::ModifyEventHyperDbg(
            kSmokeActionEventTag, hinv::vmm::sdk::ModifyEventsType::QueryState,
            actionEventReenabledQueried);
    state.Check("Enable and query action event",
                actionEventEnableQuery && actionEventReenabledQueried);

    bool ignoredActionEventState = false;
    state.Check("Clear action event", actionEventRegistered &&
                hinv::vmm::ModifyEventHyperDbg(
                    kSmokeActionEventTag, hinv::vmm::sdk::ModifyEventsType::Clear,
                    ignoredActionEventState));

    if (scriptSmoke) {
        std::vector<uint8_t> condition;
        uint32_t conditionPointer = 0;
        const bool conditionCompiled = hinv::vmm::CompileUserScriptHyperDbg(
            "1 == 1", condition, conditionPointer);
        state.Check("Compile event condition", conditionCompiled &&
                    conditionPointer != 0);

        constexpr uint64_t kSmokeConditionEventTag = 0x48494E565F434E44ULL;
        event = {};
        event.CoreId = hinv::vmm::sdk::kAllCores;
        event.ProcessId = hinv::vmm::sdk::kAllProcesses;
        event.EventStage = hinv::vmm::sdk::EventStage::Pre;
        event.HasCustomOutput = 1;
        event.OutputSourceTags[0] = kSmokeConditionEventTag;
        event.Tag = kSmokeConditionEventTag;
        event.EventType = hinv::vmm::sdk::EventType::CpuidInstructionExecution;
        const bool conditionEventRegistered = conditionCompiled &&
            hinv::vmm::RegisterEventHyperDbg(event, condition);
        state.Check("Register conditional custom-output event",
                    conditionEventRegistered);
        hinv::vmm::sdk::GeneralAction conditionAction{};
        conditionAction.EventTag = kSmokeConditionEventTag;
        conditionAction.ActionType = hinv::vmm::sdk::EventActionType::BreakToDebugger;
        const bool conditionActionAdded = conditionEventRegistered &&
            hinv::vmm::AddActionToEventHyperDbg(conditionAction, {});
        bool conditionEventEnabled = false;
        const bool conditionEventQueried = conditionActionAdded &&
            hinv::vmm::ModifyEventHyperDbg(
                kSmokeConditionEventTag,
                hinv::vmm::sdk::ModifyEventsType::QueryState,
                conditionEventEnabled);
        state.Check("Enable conditional custom-output event",
                    conditionEventQueried && conditionEventEnabled);
        bool ignoredConditionState = false;
        state.Check("Clear conditional custom-output event",
                    conditionEventRegistered &&
                    hinv::vmm::ModifyEventHyperDbg(
                        kSmokeConditionEventTag,
                        hinv::vmm::sdk::ModifyEventsType::Clear,
                        ignoredConditionState));

        std::vector<uint8_t> actionScript;
        uint32_t actionScriptPointer = 0;
        const bool actionScriptCompiled = hinv::vmm::CompileUserScriptHyperDbg(
            "1 + 2;", actionScript, actionScriptPointer);
        state.Check("Compile event action script",
                    actionScriptCompiled && actionScriptPointer != 0);

        constexpr uint64_t kSmokeScriptActionEventTag = 0x48494E565F534352ULL;
        event = {};
        event.CoreId = hinv::vmm::sdk::kAllCores;
        event.ProcessId = GetCurrentProcessId();
        event.EventStage = hinv::vmm::sdk::EventStage::Pre;
        event.Tag = kSmokeScriptActionEventTag;
        event.EventType = hinv::vmm::sdk::EventType::CpuidInstructionExecution;
        const bool scriptActionEventRegistered = actionScriptCompiled &&
            hinv::vmm::RegisterEventHyperDbg(event, {});
        hinv::vmm::sdk::GeneralAction scriptAction{};
        scriptAction.EventTag = kSmokeScriptActionEventTag;
        scriptAction.ActionType = hinv::vmm::sdk::EventActionType::RunScript;
        scriptAction.ScriptBufferPointer = actionScriptPointer;
        const bool scriptActionAdded = scriptActionEventRegistered &&
            hinv::vmm::AddActionToEventHyperDbg(scriptAction, actionScript);
        bool scriptActionEnabled = false;
        const bool scriptActionQueried = scriptActionAdded &&
            hinv::vmm::ModifyEventHyperDbg(
                kSmokeScriptActionEventTag,
                hinv::vmm::sdk::ModifyEventsType::QueryState,
                scriptActionEnabled);
        state.Check("Register and enable RunScript action",
                    scriptActionQueried && scriptActionEnabled);
        bool ignoredScriptActionState = false;
        state.Check("Clear RunScript action", scriptActionEventRegistered &&
                    hinv::vmm::ModifyEventHyperDbg(
                        kSmokeScriptActionEventTag,
                        hinv::vmm::sdk::ModifyEventsType::Clear,
                        ignoredScriptActionState));

        constexpr uint64_t kSmokeCustomActionEventTag = 0x48494E565F435354ULL;
        event = {};
        event.CoreId = hinv::vmm::sdk::kAllCores;
        event.ProcessId = GetCurrentProcessId();
        event.EventStage = hinv::vmm::sdk::EventStage::Pre;
        event.Tag = kSmokeCustomActionEventTag;
        event.EventType = hinv::vmm::sdk::EventType::CpuidInstructionExecution;
        const bool customActionEventRegistered =
            hinv::vmm::RegisterEventHyperDbg(event, {});
        hinv::vmm::sdk::GeneralAction customAction{};
        customAction.EventTag = kSmokeCustomActionEventTag;
        customAction.ActionType = hinv::vmm::sdk::EventActionType::RunCustomCode;
        const std::vector<uint8_t> returnCode{ 0xC3 };
        const bool customActionAdded = customActionEventRegistered &&
            hinv::vmm::AddActionToEventHyperDbg(customAction, returnCode);
        bool customActionEnabled = false;
        const bool customActionQueried = customActionAdded &&
            hinv::vmm::ModifyEventHyperDbg(
                kSmokeCustomActionEventTag,
                hinv::vmm::sdk::ModifyEventsType::QueryState,
                customActionEnabled);
        state.Check("Register and enable RunCustomCode action",
                    customActionQueried && customActionEnabled);
        int cpuidResult[4]{};
        if (customTriggerSmoke && !unsafeTriggersEnabled) {
            std::cout << "[SKIP] RunCustomCode trigger requires "
                         "HINV_ENABLE_UNSAFE_HYPERDBG_TRIGGERS=1\n";
        } else if (customTriggerSmoke && customActionQueried && customActionEnabled) {
            __cpuid(cpuidResult, 0);
        }
        if (customTriggerSmoke && unsafeTriggersEnabled) {
            state.Check("Trigger RunCustomCode action",
                        customActionQueried && customActionEnabled &&
                        cpuidResult[0] != 0);
        }
        bool ignoredCustomActionState = false;
        state.Check("Clear RunCustomCode action",
                    customActionEventRegistered &&
                    hinv::vmm::ModifyEventHyperDbg(
                        kSmokeCustomActionEventTag,
                        hinv::vmm::sdk::ModifyEventsType::Clear,
                        ignoredCustomActionState));
    }

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

    std::vector<uint64_t> byteSearchResults;
    const bool byteSearchOk = hinv::vmm::SearchMemoryHyperDbg(
        reinterpret_cast<uint64_t>(localPage), kPageSize, GetCurrentProcessId(),
        hinv::vmm::sdk::SearchMemoryType::Virtual,
        hinv::vmm::sdk::SearchMemoryByteSize::Byte,
        { 0x88 }, byteSearchResults);
    bool foundByte = false;
    for (const uint64_t result : byteSearchResults) {
        if (result == reinterpret_cast<uint64_t>(localPage)) {
            foundByte = true;
            break;
        }
    }
    state.Check("Search current-process virtual byte", byteSearchOk && foundByte);

    std::vector<uint64_t> dwordSearchResults;
    const bool dwordSearchOk = hinv::vmm::SearchMemoryHyperDbg(
        reinterpret_cast<uint64_t>(localPage), kPageSize, GetCurrentProcessId(),
        hinv::vmm::sdk::SearchMemoryType::Virtual,
        hinv::vmm::sdk::SearchMemoryByteSize::Dword,
        { 0x55667788 }, dwordSearchResults);
    bool foundDword = false;
    for (const uint64_t result : dwordSearchResults) {
        if (result == reinterpret_cast<uint64_t>(localPage)) {
            foundDword = true;
            break;
        }
    }
    state.Check("Search current-process virtual dword", dwordSearchOk && foundDword);

    std::vector<uint64_t> physicalSearchResults;
    const bool physicalSearchOk = translated && hinv::vmm::SearchMemoryHyperDbg(
        physical, sizeof(kLocalInitial), GetCurrentProcessId(),
        hinv::vmm::sdk::SearchMemoryType::Physical,
        hinv::vmm::sdk::SearchMemoryByteSize::Qword,
        { kLocalInitial }, physicalSearchResults);
    bool foundPhysical = false;
    for (const uint64_t result : physicalSearchResults) {
        if (result == physical) {
            foundPhysical = true;
            break;
        }
    }
    state.Check("Search physical scratch", physicalSearchOk && foundPhysical);

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

        const uint64_t detourTarget = FindKernelExportAddress(
            kernelBase, "NtAddAtom");
        state.Check("Resolve kernel EPT execute target", detourTarget != 0);
        if (detourTarget != 0) {
            constexpr uint64_t kSmokeDetourEventTag = 0x48494E565F445452ULL;
            hinv::vmm::sdk::GeneralEventDetail detourEvent{};
            detourEvent.CoreId = hinv::vmm::sdk::kAllCores;
            detourEvent.ProcessId = GetCurrentProcessId();
            detourEvent.EventStage = hinv::vmm::sdk::EventStage::Pre;
            detourEvent.Tag = kSmokeDetourEventTag;
            detourEvent.EventType =
                hinv::vmm::sdk::EventType::HiddenHookExecuteDetours;
            detourEvent.Options.OptionalParam1 = detourTarget;
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
            state.Check("Clear opt-in EPT execute detour",
                        detourRegistered &&
                        hinv::vmm::ModifyEventHyperDbg(
                            kSmokeDetourEventTag,
                            hinv::vmm::sdk::ModifyEventsType::Clear,
                            ignoredDetourState));
        }

        if (scriptSmoke && eptTriggerSmoke) {
            std::vector<uint8_t> triggerScript;
            uint32_t triggerScriptPointer = 0;
            const bool triggerScriptCompiled = hinv::vmm::CompileUserScriptHyperDbg(
                "1 + 2;", triggerScript, triggerScriptPointer);
            state.Check("Compile EPT trigger action script",
                        triggerScriptCompiled && triggerScriptPointer != 0);

            constexpr uint64_t kSmokeEptReadTriggerTag = 0x48494E565F455452ULL;
            hinv::vmm::sdk::GeneralEventDetail readTrigger{};
            readTrigger.CoreId = hinv::vmm::sdk::kAllCores;
            readTrigger.ProcessId = GetCurrentProcessId();
            readTrigger.EventStage = hinv::vmm::sdk::EventStage::Pre;
            readTrigger.Tag = kSmokeEptReadTriggerTag;
            readTrigger.EventType = hinv::vmm::sdk::EventType::HiddenHookRead;
            readTrigger.Options.OptionalParam1 =
                reinterpret_cast<uint64_t>(localPage);
            readTrigger.Options.OptionalParam2 =
                reinterpret_cast<uint64_t>(localPage) + kPageSize - 1;
            const bool readTriggerRegistered = triggerScriptCompiled &&
                hinv::vmm::RegisterEventHyperDbg(readTrigger, {});
            hinv::vmm::sdk::GeneralAction readTriggerAction{};
            readTriggerAction.EventTag = kSmokeEptReadTriggerTag;
            readTriggerAction.ActionType = hinv::vmm::sdk::EventActionType::RunScript;
            readTriggerAction.ScriptBufferPointer = triggerScriptPointer;
            const bool readTriggerActionAdded = readTriggerRegistered &&
                hinv::vmm::AddActionToEventHyperDbg(
                    readTriggerAction, triggerScript);
            bool readTriggerEnabled = false;
            const bool readTriggerQueried = readTriggerActionAdded &&
                hinv::vmm::ModifyEventHyperDbg(
                    kSmokeEptReadTriggerTag,
                    hinv::vmm::sdk::ModifyEventsType::QueryState,
                    readTriggerEnabled);
            volatile uint8_t observedRead = 0;
            if (readTriggerQueried && readTriggerEnabled)
                observedRead = *reinterpret_cast<volatile uint8_t*>(localPage);
            state.Check("Trigger EPT read RunScript action",
                        readTriggerQueried && readTriggerEnabled &&
                        observedRead == 0x88);
            bool ignoredReadTriggerState = false;
            state.Check("Clear EPT read trigger", readTriggerRegistered &&
                        hinv::vmm::ModifyEventHyperDbg(
                            kSmokeEptReadTriggerTag,
                            hinv::vmm::sdk::ModifyEventsType::Clear,
                            ignoredReadTriggerState));

            if (!unsafeTriggersEnabled) {
                std::cout << "[SKIP] EPT execute RunScript trigger requires "
                             "HINV_ENABLE_UNSAFE_HYPERDBG_TRIGGERS=1\n";
            } else {
                const uint64_t executeTarget = FindKernelExportAddress(
                    kernelBase, "NtAddAtom");
                state.Check("Resolve kernel EPT trigger target", executeTarget != 0);
                constexpr uint64_t kSmokeEptExecuteTriggerTag =
                    0x48494E565F455458ULL;
                hinv::vmm::sdk::GeneralEventDetail executeTrigger{};
                executeTrigger.CoreId = hinv::vmm::sdk::kAllCores;
                executeTrigger.ProcessId = GetCurrentProcessId();
                executeTrigger.EventStage = hinv::vmm::sdk::EventStage::Pre;
                executeTrigger.Tag = kSmokeEptExecuteTriggerTag;
                executeTrigger.EventType =
                    hinv::vmm::sdk::EventType::HiddenHookExecuteDetours;
                executeTrigger.Options.OptionalParam1 = executeTarget;
                const bool executeTriggerRegistered = triggerScriptCompiled &&
                    executeTarget != 0 &&
                    hinv::vmm::RegisterEventHyperDbg(executeTrigger, {});
                hinv::vmm::sdk::GeneralAction executeTriggerAction{};
                executeTriggerAction.EventTag = kSmokeEptExecuteTriggerTag;
                executeTriggerAction.ActionType =
                    hinv::vmm::sdk::EventActionType::RunScript;
                executeTriggerAction.ScriptBufferPointer = triggerScriptPointer;
                const bool executeTriggerActionAdded = executeTriggerRegistered &&
                    hinv::vmm::AddActionToEventHyperDbg(
                        executeTriggerAction, triggerScript);
                bool executeTriggerEnabled = false;
                const bool executeTriggerQueried = executeTriggerActionAdded &&
                    hinv::vmm::ModifyEventHyperDbg(
                        kSmokeEptExecuteTriggerTag,
                        hinv::vmm::sdk::ModifyEventsType::QueryState,
                        executeTriggerEnabled);
                using NtAddAtomFunction = NTSTATUS(NTAPI*)(PWSTR, ULONG, PUSHORT);
                NtAddAtomFunction ntAddAtom = nullptr;
                if (HMODULE ntdll = GetModuleHandleW(L"ntdll.dll")) {
                    const FARPROC raw = GetProcAddress(ntdll, "NtAddAtom");
                    static_assert(sizeof(ntAddAtom) == sizeof(raw));
                    std::memcpy(&ntAddAtom, &raw, sizeof(raw));
                }
                bool executeTriggered = false;
                if (executeTriggerQueried && executeTriggerEnabled && ntAddAtom) {
                    wchar_t atomName[] = L"hinv";
                    USHORT atom = 0;
                    (void)ntAddAtom(atomName, sizeof(atomName) - sizeof(wchar_t), &atom);
                    executeTriggered = true;
                }
                state.Check("Trigger EPT execute RunScript action",
                            executeTriggerQueried && executeTriggerEnabled &&
                            executeTriggered);
                bool ignoredExecuteTriggerState = false;
                state.Check("Clear EPT execute trigger", executeTriggerRegistered &&
                            hinv::vmm::ModifyEventHyperDbg(
                                kSmokeEptExecuteTriggerTag,
                                hinv::vmm::sdk::ModifyEventsType::Clear,
                                ignoredExecuteTriggerState));
            }
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
        uint32_t targetThreadId = 0;
        uint64_t selectedToken = 0;
        bool targetPaused = false;
        bool commandPaused = false;
        bool commandContinued = false;
        bool scriptExecuted = false;
        bool registerRead = false;
        bool regularStep = false;
        uint64_t scriptValue = 0;
        uint64_t registerValue = 0;
        if (attached) {
            for (int attempt = 0; attempt < 200; ++attempt) {
                if (hinv::vmm::SwitchProcessHyperDbg(
                        targetPid, selectedToken, targetThreadId, targetPaused) &&
                    selectedToken == processToken && targetThreadId != 0 && targetPaused)
                    break;
                Sleep(50);
            }
            commandPaused = selectedToken == processToken &&
                targetThreadId != 0 && targetPaused;
            std::cout << "[INFO] attached token=0x" << std::hex << processToken
                      << " selected=0x" << selectedToken << std::dec
                      << " thread=" << targetThreadId
                      << " paused=" << (targetPaused ? 1 : 0) << "\n";
            if (commandPaused && scriptSmoke) {
                scriptExecuted = hinv::vmm::ExecuteTextUserScriptHyperDbg(
                    processToken, targetThreadId, "formats(1 + 2);", true, &scriptValue);
            }
            if (commandPaused) {
                registerRead = hinv::vmm::ReadUserRegisterHyperDbg(
                    processToken, targetThreadId, 0, registerValue);
                regularStep = hinv::vmm::StepUserProcessHyperDbg(
                    processToken, targetThreadId);
                if (regularStep) Sleep(100);
            }
            commandContinued = commandPaused &&
                hinv::vmm::ContinueProcessHyperDbg(processToken);
        }
        state.Check("Pause attached user process", attached && commandPaused);
        state.Check("Read paused user register", attached && registerRead);
        state.Check("Regular-step paused user thread", attached && regularStep);
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
