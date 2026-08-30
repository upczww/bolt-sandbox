#include "hook/filesystem/access_classifier.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace bolt::filesystem {

ClassifiedAccess ClassifyCreateFileRequest(
    const std::uint32_t desired_access,
    const std::uint32_t creation_disposition) noexcept {
    switch (creation_disposition) {
        case CREATE_NEW:
        case CREATE_ALWAYS:
        case OPEN_ALWAYS:
            return {Access::kWrite, protocol::FilesystemOperation::kCreate};
        case TRUNCATE_EXISTING:
            return {Access::kWrite, protocol::FilesystemOperation::kWrite};
        case OPEN_EXISTING:
            break;
        default:
            return {Access::kWrite, protocol::FilesystemOperation::kWrite};
    }

    constexpr std::uint32_t write_access =
        GENERIC_ALL | GENERIC_WRITE | DELETE | FILE_WRITE_DATA | FILE_APPEND_DATA |
        FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER |
        ACCESS_SYSTEM_SECURITY | MAXIMUM_ALLOWED;
    constexpr std::uint32_t read_access =
        GENERIC_READ | GENERIC_EXECUTE | FILE_READ_DATA | FILE_EXECUTE;
    constexpr std::uint32_t metadata_access =
        FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE;
    constexpr std::uint32_t known_access = write_access | read_access | metadata_access;

    if ((desired_access & write_access) != 0 || (desired_access & ~known_access) != 0) {
        return {Access::kWrite, protocol::FilesystemOperation::kWrite};
    }
    if ((desired_access & read_access) != 0) {
        return {Access::kRead, protocol::FilesystemOperation::kRead};
    }
    return {Access::kMetadata, protocol::FilesystemOperation::kMetadata};
}

}  // namespace bolt::filesystem
