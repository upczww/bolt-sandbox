#include "common/immutable_mapping.h"

#include <array>
#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

bool RunImmutableMappingTests() {
    constexpr std::array<std::uint8_t, 5> bytes = {1, 2, 3, 4, 5};
    bolt::common::ImmutableMapping mapping;
    if (bolt::common::ImmutableMapping::Create(
            bytes.data(), bytes.size(), mapping) !=
            bolt::common::ImmutableMappingStatus::kSuccess ||
        mapping.handle() == nullptr || mapping.length() != bytes.size()) {
        return false;
    }
    const auto* read_view = static_cast<const std::uint8_t*>(
        MapViewOfFile(mapping.handle(), FILE_MAP_READ, 0, 0, bytes.size()));
    if (read_view == nullptr) {
        return false;
    }
    bool matches = true;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        matches = matches && read_view[index] == bytes[index];
    }
    UnmapViewOfFile(read_view);
    void* write_view =
        MapViewOfFile(mapping.handle(), FILE_MAP_WRITE, 0, 0, bytes.size());
    if (write_view != nullptr) {
        UnmapViewOfFile(write_view);
        return false;
    }
    bolt::common::ImmutableMapping invalid;
    return matches && bolt::common::ImmutableMapping::Create(nullptr, 0, invalid) ==
                          bolt::common::ImmutableMappingStatus::kInvalidArgument;
}
