#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

namespace bolt::registry {

enum class RegistryHive : std::uint8_t {
    kClassesRoot = 0,
    kCurrentUser = 1,
    kLocalMachine = 2,
    kUsers = 3,
    kCurrentConfig = 4,
};

enum class RegistryAccess : std::uint8_t {
    kRead,
    kWrite,
    kEnumerate,
};

enum class RegistryDecision : std::uint8_t {
    kAllow,
    kDeny,
    kInheritUser,
};

enum class RegistryPolicyLoadStatus : std::uint8_t {
    kValid,
    kInvalidPayload,
    kInvalidRegistryPolicy,
    kOutOfMemory,
};

class RegistryPolicy final {
  public:
    ~RegistryPolicy();

    RegistryPolicy(const RegistryPolicy&) = delete;
    RegistryPolicy& operator=(const RegistryPolicy&) = delete;

    static RegistryPolicyLoadStatus Load(
        const std::uint8_t* payload,
        std::size_t length,
        std::unique_ptr<RegistryPolicy>& policy) noexcept;

    [[nodiscard]] RegistryDecision Decide(
        RegistryHive hive,
        const wchar_t* relative_key,
        RegistryAccess access) const noexcept;

    [[nodiscard]] bool MayTraverse(
        RegistryHive hive,
        const wchar_t* relative_key) const noexcept;

  private:
    struct Impl;
    explicit RegistryPolicy(std::unique_ptr<Impl> implementation) noexcept;

    std::unique_ptr<Impl> implementation_;
};

}  // namespace bolt::registry
