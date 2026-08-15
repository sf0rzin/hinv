#include <iostream>
#include <string>

#include "../src/hinv-core/hinv_client.hpp"
#include "../src/hinv-core/hinv_util.hpp"

int main() {
    int failures = 0;
    auto check = [&](bool condition, const char* name) {
        if (condition) std::cout << "[PASS] " << name << "\n";
        else {
            std::cout << "[FAIL] " << name << "\n";
            ++failures;
        }
    };

    static_assert(hinv::ipc::kMaxMessageBytes == 64 * 1024);
    hinv::Client client;
    check(!client.IsConnected(), "client starts disconnected");

    const auto noConnection = client.LoadDriver(std::string("C:/missing.sys"));
    check(noConnection.state == hinv::ClientCommandState::Failed,
          "failed connect is not reported as success");

    hinv::ClientCommandResult unknown{ hinv::ClientCommandState::Unknown, {} };
    check(unknown.Unknown() && !unknown.Succeeded() && !static_cast<bool>(unknown),
          "unknown command result is distinct from success");

    std::string wide;
    check(hinv::util::WideToUtf8(L"driver.sys", &wide) && wide == "driver.sys",
          "SDK path conversion is strict UTF-8");
    check(hinv::ipc::OperationTimeoutMs() >= 1000,
          "IPC timeout has a bounded configurable default");
    return failures == 0 ? 0 : 1;
}
