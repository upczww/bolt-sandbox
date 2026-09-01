#include "protocol/projected_workspace_protocol.h"

#include <vector>

bool RunProjectedWorkspaceProtocolTests() {
    const bolt::protocol::ProjectedWorkspaceRequest expected{
        L"C:\\source", L"C:\\projection", 100, 1'048'576};
    std::vector<std::uint8_t> encoded;
    bolt::protocol::ProjectedWorkspaceRequest decoded{};
    if (bolt::protocol::EncodeProjectedWorkspaceRequest(expected, encoded) !=
            bolt::protocol::ProjectedWorkspaceProtocolStatus::kSuccess ||
        bolt::protocol::DecodeProjectedWorkspaceRequest(
            encoded.data(), encoded.size(), decoded) !=
            bolt::protocol::ProjectedWorkspaceProtocolStatus::kSuccess ||
        !(decoded == expected)) {
        return false;
    }
    auto tampered = encoded;
    tampered.back() ^= 1;
    if (bolt::protocol::DecodeProjectedWorkspaceRequest(
            tampered.data(), tampered.size(), decoded) !=
        bolt::protocol::ProjectedWorkspaceProtocolStatus::kDigestMismatch) {
        return false;
    }
    const auto ready = bolt::protocol::EncodeProjectedWorkspaceResponse(
        bolt::protocol::ProjectedWorkspaceResponseKind::kReady,
        bolt::protocol::ProjectedWorkspaceResult::kUnavailable);
    bolt::protocol::ProjectedWorkspaceResult result{};
    if (bolt::protocol::DecodeProjectedWorkspaceResponse(
            ready.data(), ready.size(),
            bolt::protocol::ProjectedWorkspaceResponseKind::kReady,
            result) !=
            bolt::protocol::ProjectedWorkspaceProtocolStatus::kSuccess ||
        result != bolt::protocol::ProjectedWorkspaceResult::kUnavailable) {
        return false;
    }
    const auto control = bolt::protocol::EncodeProjectedWorkspaceControl(
        bolt::protocol::ProjectedWorkspaceControl::kMaterialize);
    bolt::protocol::ProjectedWorkspaceControl decoded_control{};
    return bolt::protocol::DecodeProjectedWorkspaceControl(
               control.data(), control.size(), decoded_control) ==
               bolt::protocol::ProjectedWorkspaceProtocolStatus::kSuccess &&
           decoded_control ==
               bolt::protocol::ProjectedWorkspaceControl::kMaterialize;
}
