#include "common/projfs_api.h"

namespace bolt::common {
namespace {

template <typename Function>
Function Resolve(const HMODULE module, const char* const name) noexcept {
    return reinterpret_cast<Function>(GetProcAddress(module, name));
}

}  // namespace

ProjfsApi::~ProjfsApi() noexcept {
    Close();
}

ProjfsStatus ProjfsApi::Load(ProjfsApi& output) noexcept {
    output.Close();
    const HMODULE module = LoadLibraryExW(
        L"ProjectedFSLib.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module == nullptr) {
        return ProjfsStatus::kUnavailable;
    }

    ProjfsApi loaded;
    loaded.module_ = module;
    loaded.mark_directory_as_placeholder_ =
        Resolve<MarkDirectoryAsPlaceholderFunction>(
            module, "PrjMarkDirectoryAsPlaceholder");
    loaded.start_virtualizing_ = Resolve<StartVirtualizingFunction>(
        module, "PrjStartVirtualizing");
    loaded.stop_virtualizing_ = Resolve<StopVirtualizingFunction>(
        module, "PrjStopVirtualizing");
    loaded.write_placeholder_info_ = Resolve<WritePlaceholderInfoFunction>(
        module, "PrjWritePlaceholderInfo");
    loaded.write_file_data_ = Resolve<WriteFileDataFunction>(
        module, "PrjWriteFileData");
    loaded.fill_dir_entry_buffer_ = Resolve<FillDirEntryBufferFunction>(
        module, "PrjFillDirEntryBuffer");
    loaded.file_name_match_ = Resolve<FileNameMatchFunction>(
        module, "PrjFileNameMatch");
    loaded.file_name_compare_ = Resolve<FileNameCompareFunction>(
        module, "PrjFileNameCompare");
    loaded.allocate_aligned_buffer_ = Resolve<AllocateAlignedBufferFunction>(
        module, "PrjAllocateAlignedBuffer");
    loaded.free_aligned_buffer_ = Resolve<FreeAlignedBufferFunction>(
        module, "PrjFreeAlignedBuffer");
    loaded.get_virtualization_instance_info_ =
        Resolve<GetVirtualizationInstanceInfoFunction>(
            module, "PrjGetVirtualizationInstanceInfo");
    if (!loaded.available()) {
        return ProjfsStatus::kInvalidExports;
    }

    output.module_ = loaded.module_;
    output.mark_directory_as_placeholder_ =
        loaded.mark_directory_as_placeholder_;
    output.start_virtualizing_ = loaded.start_virtualizing_;
    output.stop_virtualizing_ = loaded.stop_virtualizing_;
    output.write_placeholder_info_ = loaded.write_placeholder_info_;
    output.write_file_data_ = loaded.write_file_data_;
    output.fill_dir_entry_buffer_ = loaded.fill_dir_entry_buffer_;
    output.file_name_match_ = loaded.file_name_match_;
    output.file_name_compare_ = loaded.file_name_compare_;
    output.allocate_aligned_buffer_ = loaded.allocate_aligned_buffer_;
    output.free_aligned_buffer_ = loaded.free_aligned_buffer_;
    output.get_virtualization_instance_info_ =
        loaded.get_virtualization_instance_info_;
    loaded.module_ = nullptr;
    loaded.Close();
    return ProjfsStatus::kSuccess;
}

bool ProjfsApi::available() const noexcept {
    return module_ != nullptr && mark_directory_as_placeholder_ != nullptr &&
           start_virtualizing_ != nullptr && stop_virtualizing_ != nullptr &&
           write_placeholder_info_ != nullptr && write_file_data_ != nullptr &&
           fill_dir_entry_buffer_ != nullptr && file_name_match_ != nullptr &&
           file_name_compare_ != nullptr &&
           allocate_aligned_buffer_ != nullptr && free_aligned_buffer_ != nullptr &&
           get_virtualization_instance_info_ != nullptr;
}

ProjfsApi::MarkDirectoryAsPlaceholderFunction
ProjfsApi::mark_directory_as_placeholder() const noexcept {
    return mark_directory_as_placeholder_;
}

ProjfsApi::StartVirtualizingFunction ProjfsApi::start_virtualizing() const noexcept {
    return start_virtualizing_;
}

ProjfsApi::StopVirtualizingFunction ProjfsApi::stop_virtualizing() const noexcept {
    return stop_virtualizing_;
}

ProjfsApi::WritePlaceholderInfoFunction
ProjfsApi::write_placeholder_info() const noexcept {
    return write_placeholder_info_;
}

ProjfsApi::WriteFileDataFunction ProjfsApi::write_file_data() const noexcept {
    return write_file_data_;
}

ProjfsApi::FillDirEntryBufferFunction
ProjfsApi::fill_dir_entry_buffer() const noexcept {
    return fill_dir_entry_buffer_;
}

ProjfsApi::FileNameMatchFunction ProjfsApi::file_name_match() const noexcept {
    return file_name_match_;
}

ProjfsApi::FileNameCompareFunction
ProjfsApi::file_name_compare() const noexcept {
    return file_name_compare_;
}

ProjfsApi::AllocateAlignedBufferFunction
ProjfsApi::allocate_aligned_buffer() const noexcept {
    return allocate_aligned_buffer_;
}

ProjfsApi::FreeAlignedBufferFunction ProjfsApi::free_aligned_buffer() const noexcept {
    return free_aligned_buffer_;
}

ProjfsApi::GetVirtualizationInstanceInfoFunction
ProjfsApi::get_virtualization_instance_info() const noexcept {
    return get_virtualization_instance_info_;
}

void ProjfsApi::Close() noexcept {
    if (module_ != nullptr) {
        FreeLibrary(module_);
    }
    module_ = nullptr;
    mark_directory_as_placeholder_ = nullptr;
    start_virtualizing_ = nullptr;
    stop_virtualizing_ = nullptr;
    write_placeholder_info_ = nullptr;
    write_file_data_ = nullptr;
    fill_dir_entry_buffer_ = nullptr;
    file_name_match_ = nullptr;
    file_name_compare_ = nullptr;
    allocate_aligned_buffer_ = nullptr;
    free_aligned_buffer_ = nullptr;
    get_virtualization_instance_info_ = nullptr;
}

}  // namespace bolt::common
