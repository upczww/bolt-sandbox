// Minimal compatibility boundary for BuildXL CanonicalizedPath. The complete
// BuildXL manifest policy types are intentionally not imported.
#pragma once

#include <cassert>
#include <memory>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "StringOperations.h"

using std::unique_ptr;

enum PathType {
    Null,
    Win32Nt,
    LocalDevice,
    Win32,
};
