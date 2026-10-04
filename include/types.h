#pragma once

#include <ntifs.h>
#include <ntddk.h>

#define POOL_TAG_MOD  'LDOM'
#define POOL_TAG_BUF  'FFUB'

typedef struct _MODULE_INFO {
    ULONG_PTR BaseAddress;
    ULONG     ImageSize;
} MODULE_INFO, *PMODULE_INFO;

typedef struct _PATCH_CONTEXT {
    ULONGLONG AnchorAddress;
    ULONGLONG PatchAddresses[8];
    ULONG     PatchCount;
} PATCH_CONTEXT, *PPATCH_CONTEXT;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11,
} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG                          NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef NTSTATUS (NTAPI *PFN_ZWQUERYSYSTEMINFORMATION)(
    IN  SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID                 SystemInformation,
    IN  ULONG                    SystemInformationLength,
    OUT PULONG                   ReturnLength OPTIONAL
);
