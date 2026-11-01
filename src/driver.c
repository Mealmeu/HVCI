#include "../include/ci_patch.h"

DRIVER_UNLOAD DriverUnload;

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
}

DRIVER_INITIALIZE DriverEntry;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    return PerformHvciBypass();
}
