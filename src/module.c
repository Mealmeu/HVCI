#include "../include/module.h"
#include "../include/memory.h"

MODULE_INFO GetKernelModuleByName(const char *Name) {
    MODULE_INFO result = { 0 };

    if (!Name) {
        return result;
    }

    UNICODE_STRING          funcName = RTL_CONSTANT_STRING(L"ZwQuerySystemInformation");
    PFN_ZWQUERYSYSTEMINFORMATION ZwQSI;
    ULONG                   bufSize  = 0;
    PVOID                   buf      = NULL;
    NTSTATUS                status;

    ZwQSI = (PFN_ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&funcName);
    if (!ZwQSI) {
        return result;
    }

    status = ZwQSI(SystemModuleInformation, NULL, 0, &bufSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH || bufSize == 0) {
        return result;
    }

    bufSize += 0x200;
    buf = SafeAllocNonPaged(bufSize, POOL_TAG_MOD);
    if (!buf) {
        return result;
    }

    status = ZwQSI(SystemModuleInformation, buf, bufSize, &bufSize);
    if (!NT_SUCCESS(status)) {
        SafeFree(buf, POOL_TAG_MOD);
        return result;
    }

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)buf;

    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        PRTL_PROCESS_MODULE_INFORMATION mod = &modules->Modules[i];
        const char *fileName = (const char *)mod->FullPathName + mod->OffsetToFileName;

        if (_stricmp(fileName, Name) == 0) {
            result.BaseAddress = (ULONG_PTR)mod->ImageBase;
            result.ImageSize   = mod->ImageSize;
            break;
        }
    }

    SafeFree(buf, POOL_TAG_MOD);
    return result;
}
