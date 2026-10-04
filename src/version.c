#include "../include/version.h"

typedef NTSTATUS (NTAPI *PFN_RTLGETVERSION)(PRTL_OSVERSIONINFOEXW);

NTSTATUS GetOsVersion(POS_VERSION Version) {
    if (!Version) {
        return STATUS_INVALID_PARAMETER;
    }

    UNICODE_STRING        funcName = RTL_CONSTANT_STRING(L"RtlGetVersion");
    PFN_RTLGETVERSION     RtlGetVersionFn;
    RTL_OSVERSIONINFOEXW  osi = { 0 };
    NTSTATUS              status;

    RtlGetVersionFn = (PFN_RTLGETVERSION)MmGetSystemRoutineAddress(&funcName);
    if (!RtlGetVersionFn) {
        return STATUS_NOT_FOUND;
    }

    osi.dwOSVersionInfoSize = sizeof(osi);
    status = RtlGetVersionFn(&osi);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Version->Major    = osi.dwMajorVersion;
    Version->Minor    = osi.dwMinorVersion;
    Version->Build    = osi.dwBuildNumber;
    Version->Revision = osi.wServicePackMajor;

    return STATUS_SUCCESS;
}
