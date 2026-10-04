#pragma once

#include "types.h"

PVOID  SafeAllocNonPaged(SIZE_T Size, ULONG Tag);
VOID   SafeFree(PVOID Buffer, ULONG Tag);
BOOLEAN SafeReadByte(ULONGLONG Address, PUCHAR Out);
NTSTATUS SafeWriteByte(ULONGLONG Address, UCHAR Value);
