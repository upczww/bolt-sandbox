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

union PsCreateInfoData {
    struct {
        ULONG init_flags;
        ACCESS_MASK additional_file_access;
    } initial_state;
    ULONG_PTR alignment;
#if defined(_WIN64)
    UCHAR storage[72];
#else
    UCHAR storage[64];
#endif
};

struct PsCreateInfo {
    SIZE_T size;
    ULONG state;
    PsCreateInfoData data;
};

struct PsAttribute {
    ULONG_PTR attribute;
    SIZE_T size;
    union {
        ULONG_PTR value;
        PVOID value_ptr;
    };
    SIZE_T* return_length;
};

struct PsAttributeList {
    SIZE_T total_length;
    PsAttribute attributes[1];
};

#if defined(_WIN64)
static_assert(sizeof(SectionImageInformation) == 64);
static_assert(sizeof(RtlUserProcessInformation) == 104);
static_assert(sizeof(PsCreateInfo) == 88);
static_assert(sizeof(PsAttribute) == 32);
static_assert(sizeof(PsAttributeList) == 40);
#else
static_assert(sizeof(SectionImageInformation) == 48);
static_assert(sizeof(RtlUserProcessInformation) == 68);
static_assert(sizeof(PsCreateInfo) == 72);
static_assert(sizeof(PsAttribute) == 16);
static_assert(sizeof(PsAttributeList) == 20);
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

using NtCreateUserProcessFunction = NTSTATUS(NTAPI*)(
    PHANDLE,
    PHANDLE,
    ACCESS_MASK,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    POBJECT_ATTRIBUTES,
    ULONG,
    ULONG,
    PRTL_USER_PROCESS_PARAMETERS,
    PsCreateInfo*,
    PsAttributeList*);

}  // namespace bolt::process::native
