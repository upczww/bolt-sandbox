// Narrow Bolt-facing declaration for the BuildXL path decomposition adapter.
#pragma once

#include <string>
#include <vector>

int TryDecomposePath(const std::wstring& path, std::vector<std::wstring>& elements);
