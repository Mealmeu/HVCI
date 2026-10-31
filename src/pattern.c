#include "../include/pattern.h"
#include "../include/memory.h"

ULONGLONG ScanPattern(ULONG_PTR Base, ULONG Size, PCHAR Pattern, PCHAR Mask) {
    SIZE_T maskLen = strlen(Mask);

    if (maskLen == 0 || Size < maskLen) {
        return 0;
    }

    SIZE_T limit = Size - maskLen;

    for (SIZE_T i = 0; i < limit; i++) {
        BOOLEAN matched = TRUE;
        BOOLEAN faulted = FALSE;

        for (SIZE_T j = 0; j < maskLen; j++) {
            UCHAR current;
            if (!SafeReadByte(Base + i + j, &current)) {
                matched = FALSE;
                faulted = TRUE;
                break;
            }
            if (Mask[j] != '?' && Pattern[j] != (CHAR)current) {
                matched = FALSE;
                break;
            }
        }

        if (faulted) break;
        if (matched) return (ULONGLONG)(Base + i);
    }

    return 0;
}
