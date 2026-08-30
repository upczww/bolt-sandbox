#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace bolt::filesystem {

enum class Access : std::uint8_t {
    kRead,
    kWrite,
    kMetadata,
};

enum class Decision : std::uint8_t {
    kAllow,
    kDeny,
    kInheritUser,
};

enum class PolicyLoadStatus : std::uint8_t {
    kValid,
    kInvalidPayload,
    kInvalidFilesystemPolicy,
    kOutOfMemory,
};

struct PolicyEvaluation {
    Decision decision = Decision::kDeny;
    std::wstring normalized_path;
};

class PolicyView {
  public:
    virtual ~PolicyView() = default;

    [[nodiscard]] virtual PolicyEvaluation Evaluate(
        const wchar_t* path,
        Access access) const noexcept = 0;

    [[nodiscard]] Decision Decide(const wchar_t* path, Access access) const noexcept {
        return Evaluate(path, access).decision;
    }
};

class FilesystemPolicy final : public PolicyView {
  public:
    ~FilesystemPolicy() override;

    FilesystemPolicy(const FilesystemPolicy&) = delete;
    FilesystemPolicy& operator=(const FilesystemPolicy&) = delete;

    static PolicyLoadStatus Load(
        const std::uint8_t* payload,
        std::size_t length,
        std::unique_ptr<FilesystemPolicy>& policy) noexcept;

    [[nodiscard]] PolicyEvaluation Evaluate(
        const wchar_t* path,
        Access access) const noexcept override;

  private:
    struct Impl;
    explicit FilesystemPolicy(std::unique_ptr<Impl> implementation) noexcept;

    std::unique_ptr<Impl> implementation_;
};

}  // namespace bolt::filesystem
