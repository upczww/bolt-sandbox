// Adapted from Microsoft BuildXL UtilityHelpers.h at the revision recorded in
// native/third_party/buildxl/provenance.json. Licensed under the MIT License.
#pragma once

#include <algorithm>
#include <cassert>
#include <cwctype>
#include <functional>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

struct CaseInsensitiveStringComparer {
    bool operator()(const std::wstring& left, const std::wstring& right) const {
        if (left.length() != right.length()) {
            return false;
        }
        if (left.data() == right.data()) {
            return true;
        }
        return std::equal(
            right.begin(), right.end(), left.begin(), [](const wchar_t left_character, const wchar_t right_character) {
                return left_character == right_character ||
                       std::towlower(left_character) == std::towlower(right_character);
            });
    }
};

struct CaseInsensitiveStringHasher {
    std::size_t operator()(const std::wstring& value) const {
        std::wstring normalized(value);
        std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](const wchar_t character) {
            return std::towlower(character);
        });
        return std::hash<std::wstring>{}(normalized);
    }
};
