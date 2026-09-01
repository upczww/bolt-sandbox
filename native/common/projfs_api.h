#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <projectedfslib.h>

namespace bolt::common {

enum class ProjfsStatus {
    kSuccess,
    kUnavailable,
    kInvalidExports,
};

class ProjfsApi final {
  public:
    using MarkDirectoryAsPlaceholderFunction =
        decltype(&PrjMarkDirectoryAsPlaceholder);
    using StartVirtualizingFunction = decltype(&PrjStartVirtualizing);
    using StopVirtualizingFunction = decltype(&PrjStopVirtualizing);
    using WritePlaceholderInfoFunction = decltype(&PrjWritePlaceholderInfo);
    using WriteFileDataFunction = decltype(&PrjWriteFileData);
    using FillDirEntryBufferFunction = decltype(&PrjFillDirEntryBuffer);
    using FileNameMatchFunction = decltype(&PrjFileNameMatch);
    using FileNameCompareFunction = decltype(&PrjFileNameCompare);
    using AllocateAlignedBufferFunction = decltype(&PrjAllocateAlignedBuffer);
    using FreeAlignedBufferFunction = decltype(&PrjFreeAlignedBuffer);
    using GetVirtualizationInstanceInfoFunction =
        decltype(&PrjGetVirtualizationInstanceInfo);

    ProjfsApi() noexcept = default;
    ~ProjfsApi() noexcept;
    ProjfsApi(const ProjfsApi&) = delete;
    ProjfsApi& operator=(const ProjfsApi&) = delete;

    static ProjfsStatus Load(ProjfsApi& output) noexcept;

    [[nodiscard]] bool available() const noexcept;
    [[nodiscard]] MarkDirectoryAsPlaceholderFunction
    mark_directory_as_placeholder() const noexcept;
    [[nodiscard]] StartVirtualizingFunction start_virtualizing() const noexcept;
    [[nodiscard]] StopVirtualizingFunction stop_virtualizing() const noexcept;
    [[nodiscard]] WritePlaceholderInfoFunction
    write_placeholder_info() const noexcept;
    [[nodiscard]] WriteFileDataFunction write_file_data() const noexcept;
    [[nodiscard]] FillDirEntryBufferFunction fill_dir_entry_buffer() const noexcept;
    [[nodiscard]] FileNameMatchFunction file_name_match() const noexcept;
    [[nodiscard]] FileNameCompareFunction file_name_compare() const noexcept;
    [[nodiscard]] AllocateAlignedBufferFunction
    allocate_aligned_buffer() const noexcept;
    [[nodiscard]] FreeAlignedBufferFunction free_aligned_buffer() const noexcept;
    [[nodiscard]] GetVirtualizationInstanceInfoFunction
    get_virtualization_instance_info() const noexcept;

  private:
    void Close() noexcept;

    HMODULE module_ = nullptr;
    MarkDirectoryAsPlaceholderFunction mark_directory_as_placeholder_ = nullptr;
    StartVirtualizingFunction start_virtualizing_ = nullptr;
    StopVirtualizingFunction stop_virtualizing_ = nullptr;
    WritePlaceholderInfoFunction write_placeholder_info_ = nullptr;
    WriteFileDataFunction write_file_data_ = nullptr;
    FillDirEntryBufferFunction fill_dir_entry_buffer_ = nullptr;
    FileNameMatchFunction file_name_match_ = nullptr;
    FileNameCompareFunction file_name_compare_ = nullptr;
    AllocateAlignedBufferFunction allocate_aligned_buffer_ = nullptr;
    FreeAlignedBufferFunction free_aligned_buffer_ = nullptr;
    GetVirtualizationInstanceInfoFunction get_virtualization_instance_info_ = nullptr;
};

}  // namespace bolt::common
