#pragma once

#include <cstddef>
#include <cstdint>

namespace hinv::vmm::sdk {

// Wire definitions audited against HyperDbg v0.23:
// fa816b40622c2f39ed0232ecdeaca0f159b5d326.
constexpr uint32_t kVersion = 0x23;
constexpr uint32_t kAllCores = 0xffffffffu;
constexpr uint32_t kAllProcesses = 0xffffffffu;
constexpr uint64_t kAllEventTags = 0xffffffffffffffffULL;
constexpr uint32_t kMaximumSearchResults = 0x1000;
constexpr uint32_t kMaximumInstructionSize = 16;

enum class MsrAction : uint32_t {
    Read = 0,
    Write = 1,
};

struct ReadAndWriteOnMsr {
    uint64_t Msr;
    uint32_t CoreNumber;
    MsrAction ActionType;
    uint64_t Value;
};

static_assert(sizeof(ReadAndWriteOnMsr) == 24);
static_assert(offsetof(ReadAndWriteOnMsr, CoreNumber) == 8);
static_assert(offsetof(ReadAndWriteOnMsr, ActionType) == 12);
static_assert(offsetof(ReadAndWriteOnMsr, Value) == 16);

struct ReadPageTableEntriesDetails {
    uint64_t VirtualAddress;
    uint32_t ProcessId;
    uint64_t Pml4eVirtualAddress;
    uint64_t Pml4eValue;
    uint64_t PdpteVirtualAddress;
    uint64_t PdpteValue;
    uint64_t PdeVirtualAddress;
    uint64_t PdeValue;
    uint64_t PteVirtualAddress;
    uint64_t PteValue;
    uint32_t KernelStatus;
};

static_assert(sizeof(ReadPageTableEntriesDetails) == 88);
static_assert(offsetof(ReadPageTableEntriesDetails, Pml4eVirtualAddress) == 16);
static_assert(offsetof(ReadPageTableEntriesDetails, KernelStatus) == 80);

enum class SearchMemoryType : uint32_t {
    Physical = 0,
    Virtual = 1,
    PhysicalFromVirtual = 2,
};

enum class SearchMemoryByteSize : uint32_t {
    Byte = 0,
    Dword = 1,
    Qword = 2,
};

struct SearchMemoryRequest {
    uint64_t Address;
    uint64_t Length;
    uint32_t ProcessId;
    SearchMemoryType MemoryType;
    SearchMemoryByteSize ByteSize;
    uint32_t CountOf64Chunks;
    uint32_t FinalStructureSize;
};

static_assert(sizeof(SearchMemoryRequest) == 40);
static_assert(offsetof(SearchMemoryRequest, ProcessId) == 16);
static_assert(offsetof(SearchMemoryRequest, FinalStructureSize) == 32);

enum class ModifyEventsType : uint32_t {
    QueryState = 0,
    Enable = 1,
    Disable = 2,
    Clear = 3,
};

struct ModifyEventsRequest {
    uint64_t Tag;
    uint64_t KernelStatus;
    ModifyEventsType TypeOfAction;
    uint8_t IsEnabled;
};

static_assert(sizeof(ModifyEventsRequest) == 24);
static_assert(offsetof(ModifyEventsRequest, TypeOfAction) == 16);
static_assert(offsetof(ModifyEventsRequest, IsEnabled) == 20);

enum class AttachDetachAction : uint32_t {
    Attach = 0,
    Detach = 1,
    RemoveHooks = 2,
    KillProcess = 3,
    ContinueProcess = 4,
    PauseProcess = 5,
    SwitchByProcessOrThread = 6,
    QueryActiveDebuggingCount = 7,
};

struct AttachDetachProcessRequest {
    uint8_t IsStartingNewProcess;
    uint32_t ProcessId;
    uint32_t ThreadId;
    uint8_t CheckCallbackAtFirstInstruction;
    uint8_t Is32Bit;
    uint64_t Rip;
    uint8_t InstructionBytesOnRip[kMaximumInstructionSize];
    uint32_t SizeOfInstruction;
    uint8_t IsPaused;
    AttachDetachAction Action;
    uint32_t CountOfActiveDebuggingThreadsAndProcesses;
    uint64_t Token;
    uint64_t Result;
};

static_assert(sizeof(AttachDetachProcessRequest) == 72);
static_assert(offsetof(AttachDetachProcessRequest, Rip) == 16);
static_assert(offsetof(AttachDetachProcessRequest, Action) == 48);
static_assert(offsetof(AttachDetachProcessRequest, Result) == 64);

enum class UserDebuggerCommandAction : uint32_t {
    None = 0,
    Pause = 1,
    RegularStep = 2,
    ReadRegisters = 3,
    ExecuteScriptBuffer = 4,
};

struct UserDebuggerCommandActionPacket {
    UserDebuggerCommandAction ActionType;
    uint64_t OptionalParam1;
    uint64_t OptionalParam2;
    uint64_t OptionalParam3;
    uint64_t OptionalParam4;
};

struct UserDebuggerCommandPacket {
    UserDebuggerCommandActionPacket UdAction;
    uint64_t ProcessDebuggingDetailToken;
    uint32_t TargetThreadId;
    uint8_t ApplyToAllPausedThreads;
    uint8_t WaitForEventCompletion;
    uint32_t Result;
};

static_assert(sizeof(UserDebuggerCommandActionPacket) == 40);
static_assert(sizeof(UserDebuggerCommandPacket) == 64);
static_assert(offsetof(UserDebuggerCommandPacket, ProcessDebuggingDetailToken) == 40);
static_assert(offsetof(UserDebuggerCommandPacket, Result) == 56);

struct DebuggeeScriptPacket {
    uint32_t ScriptBufferSize;
    uint32_t ScriptBufferPointer;
    uint8_t IsFormat;
    uint64_t FormatValue;
    uint32_t Result;
};

static_assert(sizeof(DebuggeeScriptPacket) == 32);
static_assert(offsetof(DebuggeeScriptPacket, FormatValue) == 16);
static_assert(offsetof(DebuggeeScriptPacket, Result) == 24);

enum class EventActionType : uint32_t {
    BreakToDebugger = 0,
    RunScript = 1,
    RunCustomCode = 2,
};

enum class EventStage : uint32_t {
    Invalid = 0,
    Pre = 1,
    Post = 2,
    All = 3,
};

enum class EventType : uint32_t {
    HiddenHookReadWriteExecute = 0,
    HiddenHookReadWrite = 1,
    HiddenHookReadExecute = 2,
    HiddenHookWriteExecute = 3,
    HiddenHookRead = 4,
    HiddenHookWrite = 5,
    HiddenHookExecute = 6,
    HiddenHookExecuteDetours = 7,
    HiddenHookExecuteCc = 8,
    SyscallHookEferSyscall = 9,
    SyscallHookEferSysret = 10,
    CpuidInstructionExecution = 11,
    RdmsrInstructionExecution = 12,
    WrmsrInstructionExecution = 13,
    InInstructionExecution = 14,
    OutInstructionExecution = 15,
    ExceptionOccurred = 16,
    ExternalInterruptOccurred = 17,
    DebugRegistersAccessed = 18,
    TscInstructionExecution = 19,
    PmcInstructionExecution = 20,
    VmcallInstructionExecution = 21,
    ControlRegisterModified = 22,
    ControlRegisterRead = 23,
    ControlRegister3Modified = 24,
    TrapExecutionModeChanged = 25,
    TrapExecutionInstructionTrace = 26,
    XsetbvInstructionExecution = 27,
};

struct EventOptions {
    uint64_t OptionalParam1;
    uint64_t OptionalParam2;
    uint64_t OptionalParam3;
    uint64_t OptionalParam4;
    uint64_t OptionalParam5;
    uint64_t OptionalParam6;
};

struct ListEntry {
    uintptr_t Flink;
    uintptr_t Blink;
};

struct GeneralEventDetail {
    ListEntry CommandsEventList;
    uint32_t CoreId;
    uint32_t ProcessId;
    uint8_t IsEnabled;
    uint8_t EnableShortCircuiting;
    EventStage EventStage;
    uint8_t HasCustomOutput;
    uint64_t OutputSourceTags[5];
    uint32_t CountOfActions;
    uint64_t Tag;
    EventType EventType;
    EventOptions Options;
    uintptr_t CommandStringBuffer;
    uint32_t ConditionBufferSize;
};

struct GeneralAction {
    uint64_t EventTag;
    EventActionType ActionType;
    uint8_t ImmediateMessagePassing;
    uint32_t PreAllocatedBuffer;
    uint32_t CustomCodeBufferSize;
    uint32_t ScriptBufferSize;
    uint32_t ScriptBufferPointer;
};

struct EventAndActionResult {
    uint8_t IsSuccessful;
    uint32_t Error;
};

static_assert(sizeof(EventOptions) == 48);
static_assert(sizeof(GeneralEventDetail) == 168);
static_assert(offsetof(GeneralEventDetail, OutputSourceTags) == 40);
static_assert(offsetof(GeneralEventDetail, Options) == 104);
static_assert(sizeof(GeneralAction) == 32);
static_assert(sizeof(EventAndActionResult) == 8);

} // namespace hinv::vmm::sdk
