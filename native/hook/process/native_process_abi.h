#pragma once

// Narrow ABI adaptation from winsiderss/phnt at revision
// 53fbbdc5b5d2b08761db1c7b26bfa8c820924356 (MIT). The complete phnt header
// graph is intentionally not exposed to Bolt targets; see THIRD_PARTY_NOTICES.md.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

namespace bolt::process::native {

struct SectionImageInformation {
    PVOID transfer_address;
    ULONG zero_bits;
    SIZE_T maximum_stack_size;
    SIZE_T committed_stack_size;
    ULONG subsystem_type;
    ULONG subsystem_version;
    ULONG operating_system_version;
    USHORT image_characteristics;
    USHORT dll_characteristics;
    USHORT machine;
    BOOLEAN image_contains_code;
    UCHAR image_flags;
    ULONG loader_flags;
    ULONG image_file_size;
    ULONG checksum;
};

struct RtlUserProcessInformation {
    ULONG length;
    HANDLE process;
    HANDLE thread;
    CLIENT_ID client_id;
    SectionImageInformation image_information;
};

#if defined(_WIN64)
static_assert(sizeof(SectionImageInformation) == 64);
static_assert(sizeof(RtlUserProcessInformation) == 104);
#else
static_assert(sizeof(SectionImageInformation) == 48);
static_assert(sizeof(RtlUserProcessInformation) == 68);
#endif

using RtlCreateUserProcessFunction = NTSTATUS(NTAPI*)(
    PCUNICODE_STRING,
    ULONG,
    PRTL_USER_PROCESS_PARAMETERS,
    PSECURITY_DESCRIPTOR,
    PSECURITY_DESCRIPTOR,
    HANDLE,
    BOOLEAN,
    HANDLE,
    HANDLE,
    RtlUserProcessInformation*);

}  // namespace bolt::process::native
