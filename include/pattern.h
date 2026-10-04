#pragma once

#include "types.h"

ULONGLONG ScanPattern(
    ULONG_PTR Base,
    ULONG     Size,
    PCHAR     Pattern,
    PCHAR     Mask
);
