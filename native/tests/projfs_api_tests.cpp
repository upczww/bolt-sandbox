#include "common/projfs_api.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

bool RunProjfsApiTests() {
    bolt::common::ProjfsApi api;
    const auto status = bolt::common::ProjfsApi::Load(api);
    if (status == bolt::common::ProjfsStatus::kSuccess) {
        return api.available();
    }
    return status == bolt::common::ProjfsStatus::kUnavailable &&
           !api.available();
}
