#pragma once
#include <windows.h>
#include <cstdint>
#include <string>

#include "hinv_byovd.hpp"

namespace hinv {
namespace hijack {

// Resolve the kernel virtual address of a named driver's DRIVER_OBJECT.
// Requires an active BYOVD backend with arbitrary kernel read/write.
uint64_t GetDriverObjectAddress(byovd::IByovdBackend* backend, const std::wstring& driverName = L"Null");

// Prepare a hijacked DriverObject context. Currently validates inputs and returns success.
// The actual field manipulation happens inside the mapper before DriverEntry is called.
bool PrepareHijackedDriverObject(byovd::IByovdBackend* backend, uint64_t targetDriverObjectAddress,
                                 uint64_t mappedDriverBase);

} // namespace hijack
} // namespace hinv
