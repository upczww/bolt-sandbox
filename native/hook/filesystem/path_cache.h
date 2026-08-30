#pragma once

namespace bolt::filesystem {

void InvalidateResolvedPathForMutation(const wchar_t* path, bool is_directory) noexcept;

}  // namespace bolt::filesystem
