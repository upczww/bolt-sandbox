#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::filesystem {

enum class HandleAccess : std::uint8_t {
    kRead = 1,
    kWrite = 2,
    kMetadata = 4,
    kEnumerate = 8,
};

class HandleAccessCache final {
  public:
    static constexpr std::size_t kCapacity = 8'192;

    HandleAccessCache() noexcept = default;
    HandleAccessCache(const HandleAccessCache&) = delete;
    HandleAccessCache& operator=(const HandleAccessCache&) = delete;

    bool Store(HANDLE handle, HandleAccess access) noexcept;
    [[nodiscard]] bool Allows(HANDLE handle, HandleAccess access) noexcept;
    void Remove(HANDLE handle) noexcept;
    [[nodiscard]] std::size_t size() noexcept;

  private:
    enum class EntryState : std::uint8_t {
        kEmpty,
        kOccupied,
        kTombstone,
    };

    struct Entry {
        HANDLE handle = nullptr;
        std::uint8_t access = 0;
        EntryState state = EntryState::kEmpty;
    };

    static std::size_t Hash(HANDLE handle) noexcept;

    SRWLOCK lock_ = SRWLOCK_INIT;
    std::array<Entry, kCapacity> entries_{};
    std::size_t size_ = 0;
};

}  // namespace bolt::filesystem
