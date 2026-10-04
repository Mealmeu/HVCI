#include "../include/memory.h"

typedef PVOID (NTAPI *PFN_EXALLOCATEPOOL2)(ULONG Flags, SIZE_T Size, ULONG Tag);

#define POOL_FLAG_NON_PAGED 0x0000000000000040ULL

static PFN_EXALLOCATEPOOL2 g_ExAllocatePool2 = NULL;
static BOOLEAN             g_PoolApiChecked  = FALSE;

static VOID EnsurePoolApi(VOID) {
    if (g_PoolApiChecked) {
        return;
    }
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"ExAllocatePool2");
    g_ExAllocatePool2   = (PFN_EXALLOCATEPOOL2)MmGetSystemRoutineAddress(&name);
    g_PoolApiChecked    = TRUE;
}

PVOID SafeAllocNonPaged(SIZE_T Size, ULONG Tag) {
    EnsurePoolApi();
    if (g_ExAllocatePool2) {
        return g_ExAllocatePool2((ULONG)POOL_FLAG_NON_PAGED, Size, Tag);
    }
#pragma warning(suppress: 4996)
    return ExAllocatePoolWithTag(NonPagedPool, Size, Tag);
}

VOID SafeFree(PVOID Buffer, ULONG Tag) {
    if (Buffer) {
        ExFreePoolWithTag(Buffer, Tag);
    }
}

BOOLEAN SafeReadByte(ULONGLONG Address, PUCHAR Out) {
    __try {
        *Out = *(volatile UCHAR *)(ULONG_PTR)Address;
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

NTSTATUS SafeWriteByte(ULONGLONG Address, UCHAR Value) {
    PMDL  mdl;
    PVOID mapped;

    mdl = IoAllocateMdl((PVOID)(ULONG_PTR)Address, sizeof(UCHAR), FALSE, FALSE, NULL);
    if (!mdl) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return STATUS_ACCESS_VIOLATION;
    }

    mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!mapped) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PMDL writeMdl = IoAllocateMdl(mapped, sizeof(UCHAR), FALSE, FALSE, NULL);
    if (!writeMdl) {
        MmUnmapLockedPages(mapped, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    MmBuildMdlForNonPagedPool(writeMdl);
    writeMdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;

    PVOID writeAddr = MmMapLockedPagesSpecifyCache(writeMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!writeAddr) {
        IoFreeMdl(writeMdl);
        MmUnmapLockedPages(mapped, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *(volatile UCHAR *)writeAddr = Value;

    MmUnmapLockedPages(writeAddr, writeMdl);
    IoFreeMdl(writeMdl);
    MmUnmapLockedPages(mapped, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    return STATUS_SUCCESS;
}
