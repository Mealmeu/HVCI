#pragma once

#include "types.h"

typedef struct _OS_VERSION {
    ULONG Major;
    ULONG Minor;
    ULONG Build;
    ULONG Revision;
} OS_VERSION, *POS_VERSION;

NTSTATUS GetOsVersion(POS_VERSION Version);
