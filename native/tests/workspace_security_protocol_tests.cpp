#include "protocol/workspace_security_protocol.h"

#include <vector>

bool RunWorkspaceSecurityProtocolTests() {
    const bolt::protocol::WorkspaceSecurityRequest expected{
        bolt::protocol::WorkspaceSecurityOperation::kCopy,
        100,
        L"C:\\work\\source",
        L"C:\\work\\staged"};
    std::vector<std::uint8_t> encoded;
    bolt::protocol::WorkspaceSecurityRequest decoded{};
    if (bolt::protocol::EncodeWorkspaceSecurityRequest(expected, encoded) !=
            bolt::protocol::WorkspaceSecurityProtocolStatus::kSuccess ||
        bolt::protocol::DecodeWorkspaceSecurityRequest(
            encoded.data(), encoded.size(), decoded) !=
            bolt::protocol::WorkspaceSecurityProtocolStatus::kSuccess ||
        !(decoded == expected)) {
        return false;
    }
    auto tampered = encoded;
    tampered.back() ^= 1;
    if (bolt::protocol::DecodeWorkspaceSecurityRequest(
            tampered.data(), tampered.size(), decoded) !=
        bolt::protocol::WorkspaceSecurityProtocolStatus::kDigestMismatch) {
        return false;
    }
    const auto response = bolt::protocol::EncodeWorkspaceSecurityResponse(
        bolt::protocol::WorkspaceSecurityResult::kMismatch);
    bolt::protocol::WorkspaceSecurityResult result{};
    return bolt::protocol::DecodeWorkspaceSecurityResponse(
               response.data(), response.size(), result) ==
               bolt::protocol::WorkspaceSecurityProtocolStatus::kSuccess &&
           result == bolt::protocol::WorkspaceSecurityResult::kMismatch;
}
