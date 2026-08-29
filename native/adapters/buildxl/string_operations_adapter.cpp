// Adapted from Microsoft BuildXL StringOperations.cpp at the revision recorded
// in native/third_party/buildxl/provenance.json. Licensed under the MIT License.
#include "StringOperations.h"

#include <cstdlib>
#include <cwchar>
#include <memory>
#include <utility>

#define BOLT_MAX_EXTENDED_PATH_LENGTH 32768
#define BOLT_MAX_EXTENDED_DIR_LENGTH \
    (BOLT_MAX_EXTENDED_PATH_LENGTH - _MAX_DRIVE - _MAX_FNAME - _MAX_EXT - 4)

int TryDecomposePath(const std::wstring& path, std::vector<std::wstring>& elements) {
    auto drive = std::make_unique<wchar_t[]>(_MAX_DRIVE);
    auto directory = std::make_unique<wchar_t[]>(BOLT_MAX_EXTENDED_DIR_LENGTH);
    auto file_name = std::make_unique<wchar_t[]>(_MAX_FNAME);
    auto extension = std::make_unique<wchar_t[]>(_MAX_EXT);

    const errno_t error = _wsplitpath_s(
        path.c_str(), drive.get(), _MAX_DRIVE, directory.get(),
        BOLT_MAX_EXTENDED_DIR_LENGTH, file_name.get(), _MAX_FNAME,
        extension.get(), _MAX_EXT);
    if (error != 0) {
        return error;
    }

    std::wstring drive_element = drive.get();
    if (!drive_element.empty()) {
        elements.push_back(std::move(drive_element));
    }

    wchar_t* context = nullptr;
    wchar_t* next = wcstok_s(directory.get(), L"\\/", &context);
    while (next != nullptr) {
        std::wstring directory_element = next;
        if (!directory_element.empty()) {
            elements.push_back(std::move(directory_element));
        }
        next = wcstok_s(nullptr, L"\\/", &context);
    }

    std::wstring filename_and_extension = file_name.get();
    filename_and_extension.append(extension.get());
    if (!filename_and_extension.empty()) {
        elements.push_back(std::move(filename_and_extension));
    }
    return 0;
}
