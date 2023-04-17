/*
 * Copyright (c) 2023 Hunt & Hackett.
 *
 * This demo project is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include <phnt_windows.h>
#include <phnt.h>
#include <stdio.h>
#include <wchar.h>

#define H2_ARGV_CLONING_MODE 1
#define H2_ARGV_PID 2
#define H2_ARGV_OPTIONS 3

typedef enum _H2_CLONING_MODE {
    H2CloneViaReflection = 1,
    H2CloneViaNativeApi
} H2_CLONING_MODE;

typedef enum _H2_KNOWN_ADDRESS {
    H2KnownAddressUserSharedData,
    H2KnownAddressHypervisorSharedUserVa,
    H2KnownAddressPebBaseAddress,
    H2KnownAddressApiSetMap,
    H2KnownAddressReadOnlySharedMemoryBase,
    H2KnownAddressAnsiCodePageData,
    H2KnownAddressGdiSharedHandleTable,
    H2KnownAddressShimData,
    H2KnownAddressActivationContextData,
    H2KnownAddressSystemDefaultActivationContextData,
    H2KnownAddressMaximum // always last
} H2_KNOWN_ADDRESS;

typedef struct _H2_KNOWN_ADDRESS_TAG {
    PVOID Address;
    PCWSTR Name;
} H2_KNOWN_ADDRESS_TAG;

typedef struct _H2_KNOWN_ADDRESSES {
    H2_KNOWN_ADDRESS_TAG Tags[H2KnownAddressMaximum];
} H2_KNOWN_ADDRESSES, *PH2_KNOWN_ADDRESSES;

VOID
NTAPI
H2CollectKnownAddresses(
    _In_ HANDLE ProcessHandle,
    _Out_ PH2_KNOWN_ADDRESSES KnownAddresses
);

NTSTATUS
NTAPI
H2QueryShortNameMappedFile(
    _In_ HANDLE Process,
    _In_ PVOID Address,
    _Out_ UNICODE_STRING* ShortName
);

PCWSTR
NTAPI
H2ProtectionToString(
    _In_ ULONG MemoryProtection
);

__success(return)
BOOLEAN
NTAPI
H2QueryClassHeap(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID Address,
    _In_ BOOLEAN WoW64,
    _Out_ PULONG HeapClass
);

PCWSTR
NTAPI
H2HeapClassToString(
    _In_ ULONG HeapClass
);

BOOLEAN
NTAPI
H2ReportStatus(
    _In_ PCWSTR LastCall,
    _In_ NTSTATUS Status
);

int wmain(int argc, wchar_t* argv[])
{
    NTSTATUS status;
    H2_CLONING_MODE cloningMode;
    BOOLEAN skipPrivateRegions;
    HANDLE hParentProcess = NULL;
    HANDLE hCloneProcess = NULL;

    wprintf_s(L"A tool for inspecting memory layout of cloned processes by Hunt & Hackett.\r\n\r\n");

    if (argc < 3)
    {
        wprintf_s(L"Usage: InspectClonedMemory.exe [cloning mode] [PID] [[options]]\r\n\r\n");
        
        wprintf_s(L"Supported cloning modes:\r\n");
        wprintf_s(L"  -r - clone via RtlCreateProcessReflection\r\n");
        wprintf_s(L"  -p - clone via NtCreateProcessEx\r\n\r\n");
        
        wprintf_s(L"Supported options:\r\n");
        wprintf_s(L"  -np - skip private regions\r\n");

        return STATUS_INVALID_PARAMETER;
    }

    if (wcscmp(argv[H2_ARGV_CLONING_MODE], L"-r") == 0)
        cloningMode = H2CloneViaReflection;
    else if (wcscmp(argv[H2_ARGV_CLONING_MODE], L"-p") == 0)
        cloningMode = H2CloneViaNativeApi;
    else
    {
        wprintf(L"ERROR: urecognized cloning mode specified.\r\n");
        return STATUS_INVALID_PARAMETER;
    }

    skipPrivateRegions = argc > H2_ARGV_OPTIONS && wcscmp(argv[H2_ARGV_OPTIONS], L"-np") == 0;

    // Enable the Debug privilege when possible
    BOOLEAN wasDebugEnabled;
    status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &wasDebugEnabled);

    if (!NT_SUCCESS(status))
        wprintf(L"WARNING: Failed to acquire the debug privilege; continuing without it...\r\n");

    // Open the target process for cloning
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;

    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)wcstoul(argv[H2_ARGV_PID], NULL, 0);
    clientId.UniqueThread = NULL;

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    status = NtOpenProcess(
        &hParentProcess,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ |
            (cloningMode == H2CloneViaReflection ? PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE : PROCESS_CREATE_PROCESS),
        &objAttr,
        &clientId
    );

    if (!H2ReportStatus(L"NtOpenProcess", status))
        goto CLEANUP;

    PPEB32 WoW64Peb;

    status = NtQueryInformationProcess(
        hParentProcess,
        ProcessWow64Information,
        &WoW64Peb,
        sizeof(WoW64Peb),
        NULL
    );

    if (!H2ReportStatus(L"NtQueryInformationProcess[ProcessWow64Information]", status))
        goto CLEANUP;

    // Clone the target process
    switch (cloningMode)
    {
        case H2CloneViaReflection:
            {
                RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION reflectionInfo;

                status = RtlCreateProcessReflection(
                    hParentProcess,
                    RTL_PROCESS_REFLECTION_FLAGS_NO_SYNCHRONIZE,
                    NULL,
                    NULL,
                    NULL,
                    &reflectionInfo
                );

                if (!H2ReportStatus(L"RtlCreateProcessReflection", status))
                    goto CLEANUP;

                NtClose(reflectionInfo.ReflectionThreadHandle);
                hCloneProcess = reflectionInfo.ReflectionProcessHandle;
            }
            break;

        case H2CloneViaNativeApi:
            {
                InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

                status = NtCreateProcessEx(
                    &hCloneProcess,
                    PROCESS_ALL_ACCESS,
                    &objAttr,
                    hParentProcess,
                    0,
                    NULL,
                    NULL,
                    NULL,
                    0
                );

                if (!H2ReportStatus(L"NtCreateProcessEx", status))
                    goto CLEANUP;
            }
            break;
    }

    // Save the default text colors
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &consoleInfo);

    WORD consoleBackground;
    consoleBackground = consoleInfo.wAttributes & 0xFFF0;

    // Collect notable addresses
    H2_KNOWN_ADDRESSES knownAddresses;
    H2CollectKnownAddresses(hParentProcess, &knownAddresses);

    // Iterate the address space of the parent
    MEMORY_BASIC_INFORMATION parentInfo;
    MEMORY_BASIC_INFORMATION cloneInfo;

    for (
        PVOID address = NULL;
        NT_SUCCESS(NtQueryVirtualMemory(
            hParentProcess,
            address,
            MemoryBasicInformation,
            &parentInfo,
            sizeof(parentInfo),
            NULL
        ));
        address = RtlOffsetToPointer(address, parentInfo.RegionSize)
    )
    {
        // Skip unused regions
        if (parentInfo.State == MEM_FREE)
            continue;

        // Allow skipping private regions
        if (skipPrivateRegions && parentInfo.Type == MEM_PRIVATE)
            continue;

        if (parentInfo.BaseAddress == parentInfo.AllocationBase)
        {
            // Report the base of allocation
            wprintf_s(L"\r\n0x%0.12zX | ", (ULONG_PTR)parentInfo.AllocationBase);

            PCWSTR memoryType;
            WORD memoryColor;

            switch (parentInfo.Type)
            {
                case MEM_PRIVATE:
                    memoryType = L"Private";
                    memoryColor = FOREGROUND_GREEN | FOREGROUND_RED;
                    break;
                case MEM_MAPPED:
                    memoryType = L"Mapped";
                    memoryColor = FOREGROUND_GREEN;
                    break;
                case MEM_IMAGE:
                    memoryType = L"Image";
                    memoryColor = FOREGROUND_BLUE | FOREGROUND_RED;
                    break;
                default:
                    memoryType = L"Unknown";
                    memoryColor = FOREGROUND_RED;
            }

            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), consoleBackground | memoryColor);
            wprintf_s(L"%s", memoryType);
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), consoleInfo.wAttributes);

            // Higighlight potentially writable shared allocations
            if (parentInfo.Type == MEM_MAPPED && (parentInfo.AllocationProtect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
            {
                wprintf_s(L" | ");
                SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), consoleBackground | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                wprintf_s(L"Writable");
                SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), consoleInfo.wAttributes);
            }

            // Tag files with their names
            if (parentInfo.Type == MEM_MAPPED || parentInfo.Type == MEM_IMAGE)
            {
                UNICODE_STRING fileName;

                if (NT_SUCCESS(H2QueryShortNameMappedFile(hParentProcess, parentInfo.AllocationBase, &fileName)))
                {
                    wprintf_s(L" | ");
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), consoleBackground | FOREGROUND_INTENSITY);
                    wprintf_s(L"%wZ", &fileName);
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), consoleInfo.wAttributes);
                    RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, fileName.Buffer);
                }
            }

            // Tag known locations
            for (H2_KNOWN_ADDRESS i = 0; i < H2KnownAddressMaximum; i++)
            {
                if (knownAddresses.Tags[i].Address && knownAddresses.Tags[i].Address == parentInfo.AllocationBase)
                {
                    wprintf_s(L" | ");
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), consoleBackground | FOREGROUND_INTENSITY);
                    wprintf_s(L"%s", knownAddresses.Tags[i].Name);
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), consoleInfo.wAttributes);
                }
            }

            wprintf_s(L"\r\n");
        }

        // Skip reserved and inaccessible sub-regions
        if (parentInfo.State == MEM_RESERVE || (parentInfo.Protect & PAGE_NOACCESS))
            continue;

        wprintf_s(L"  0x%0.12zX - 0x%0.12zX | %s%s",
            (ULONG_PTR)parentInfo.BaseAddress,
            (ULONG_PTR)RtlOffsetToPointer(parentInfo.BaseAddress, parentInfo.RegionSize - 1),
            H2ProtectionToString(parentInfo.Protect),
            parentInfo.Protect & PAGE_GUARD ? L"+G" : L""
        );

        // Tag known locations
        if (parentInfo.BaseAddress != parentInfo.AllocationBase)
        {
            for (H2_KNOWN_ADDRESS i = 0; i < H2KnownAddressMaximum; i++)
            {
                if (knownAddresses.Tags[i].Address && knownAddresses.Tags[i].Address == parentInfo.BaseAddress)
                {
                    wprintf_s(L" | ");
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), consoleBackground | FOREGROUND_INTENSITY);
                    wprintf_s(L"%s", knownAddresses.Tags[i].Name);
                    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), consoleInfo.wAttributes);
                }
            }
        }

        ULONG heapClass;

        // Tag heaps
        if (H2QueryClassHeap(hParentProcess, parentInfo.BaseAddress, !!WoW64Peb, &heapClass))
        {
            wprintf_s(L" | ");
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), consoleBackground | FOREGROUND_INTENSITY);
            wprintf_s(L"%s heap", H2HeapClassToString(heapClass));
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), consoleInfo.wAttributes);
        }

        // Query the same address for the clone
        status = NtQueryVirtualMemory(
            hCloneProcess,
            address,
            MemoryBasicInformation,
            &cloneInfo,
            sizeof(cloneInfo),
            NULL
        );

        PCWSTR comparison;

        if (!NT_SUCCESS(status))
            comparison = L"Unable to query";
        else if (cloneInfo.State == MEM_FREE)
            comparison = L"Missing";
        else if (memcmp(&parentInfo, &cloneInfo, sizeof(MEMORY_BASIC_INFORMATION)) != 0)
            comparison = L"Different";
        else
            comparison = NULL;

        // Report differences
        if (comparison)
        {
            wprintf_s(L" | ");
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), consoleBackground | FOREGROUND_RED | FOREGROUND_INTENSITY);
            wprintf_s(L"%s", comparison);
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), consoleInfo.wAttributes);
        }

        wprintf_s(L"\r\n");
    }

    wprintf_s(L"\r\nMemory enumeration completed.\r\n");
    status = STATUS_SUCCESS;

CLEANUP:
    if (hParentProcess)
        NtClose(hParentProcess);

    if (hCloneProcess)
    {
        NtTerminateProcess(hCloneProcess, STATUS_PROCESS_CLONED);
        NtClose(hCloneProcess);
    }

    return status;
}

VOID
NTAPI
H2CollectKnownAddresses(
    _In_ HANDLE ProcessHandle,
    _Out_ PH2_KNOWN_ADDRESSES KnownAddresses
)
{
    NTSTATUS status;
    memset(KnownAddresses, 0, sizeof(KnownAddresses));

    // User shared data
    KnownAddresses->Tags[H2KnownAddressUserSharedData].Name = L"USER_SHARED_DATA";
    KnownAddresses->Tags[H2KnownAddressUserSharedData].Address = USER_SHARED_DATA;

    // Hypervisor shared data
    SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION hypervisorInfo;

    status = NtQuerySystemInformation(
        SystemHypervisorSharedPageInformation,
        &hypervisorInfo,
        sizeof(hypervisorInfo),
        NULL
    );

    if (NT_SUCCESS(status))
    {
        KnownAddresses->Tags[H2KnownAddressHypervisorSharedUserVa].Name = L"HYPERVISOR_SHARED_DATA";
        KnownAddresses->Tags[H2KnownAddressHypervisorSharedUserVa].Address = hypervisorInfo.HypervisorSharedUserVa;
    }

    // PEB
    PROCESS_BASIC_INFORMATION processInfo;

    status = NtQueryInformationProcess(
        ProcessHandle,
        ProcessBasicInformation,
        &processInfo,
        sizeof(processInfo),
        NULL
    );

    if (!NT_SUCCESS(status))
        return;

    KnownAddresses->Tags[H2KnownAddressPebBaseAddress].Name = L"PEB";
    KnownAddresses->Tags[H2KnownAddressPebBaseAddress].Address = processInfo.PebBaseAddress;

    // ApiSet map
    PVOID pebField;

    status = NtReadVirtualMemory(
        ProcessHandle,
        &processInfo.PebBaseAddress->ApiSetMap,
        &pebField,
        sizeof(pebField),
        NULL
    );

    if (NT_SUCCESS(status))
    {
        KnownAddresses->Tags[H2KnownAddressApiSetMap].Name = L"ApiSetMap";
        KnownAddresses->Tags[H2KnownAddressApiSetMap].Address = pebField;
    }

    // CSR shared memory
    status = NtReadVirtualMemory(
        ProcessHandle,
        &processInfo.PebBaseAddress->ReadOnlySharedMemoryBase,
        &pebField,
        sizeof(pebField),
        NULL
    );

    if (NT_SUCCESS(status))
    {
        KnownAddresses->Tags[H2KnownAddressReadOnlySharedMemoryBase].Name = L"CSR shared memory";
        KnownAddresses->Tags[H2KnownAddressReadOnlySharedMemoryBase].Address = pebField;
    }

    // CodePage data
    status = NtReadVirtualMemory(
        ProcessHandle,
        &processInfo.PebBaseAddress->AnsiCodePageData,
        &pebField,
        sizeof(pebField),
        NULL
    );

    if (NT_SUCCESS(status))
    {
        KnownAddresses->Tags[H2KnownAddressAnsiCodePageData].Name = L"CodePage data";
        KnownAddresses->Tags[H2KnownAddressAnsiCodePageData].Address = pebField;
    }

    // GDI shared handle table
    status = NtReadVirtualMemory(
        ProcessHandle,
        &processInfo.PebBaseAddress->GdiSharedHandleTable,
        &pebField,
        sizeof(pebField),
        NULL
    );

    if (NT_SUCCESS(status))
    {
        KnownAddresses->Tags[H2KnownAddressGdiSharedHandleTable].Name = L"GDI shared handle table";
        KnownAddresses->Tags[H2KnownAddressGdiSharedHandleTable].Address = pebField;
    }

    // Shim data
    status = NtReadVirtualMemory(
        ProcessHandle,
        &processInfo.PebBaseAddress->pShimData,
        &pebField,
        sizeof(pebField),
        NULL
    );

    if (NT_SUCCESS(status))
    {
        KnownAddresses->Tags[H2KnownAddressShimData].Name = L"Shim data";
        KnownAddresses->Tags[H2KnownAddressShimData].Address = pebField;
    }

    // Activation context data
    status = NtReadVirtualMemory(
        ProcessHandle,
        &processInfo.PebBaseAddress->ActivationContextData,
        &pebField,
        sizeof(pebField),
        NULL
    );

    if (NT_SUCCESS(status))
    {
        KnownAddresses->Tags[H2KnownAddressActivationContextData].Name = L"Activation context data";
        KnownAddresses->Tags[H2KnownAddressActivationContextData].Address = pebField;
    }

    // Default activation context data
    status = NtReadVirtualMemory(
        ProcessHandle,
        &processInfo.PebBaseAddress->SystemDefaultActivationContextData,
        &pebField,
        sizeof(pebField),
        NULL
    );

    if (NT_SUCCESS(status))
    {
        KnownAddresses->Tags[H2KnownAddressSystemDefaultActivationContextData].Name = L"Default activation context data";
        KnownAddresses->Tags[H2KnownAddressSystemDefaultActivationContextData].Address = pebField;
    }
}

PCWSTR
NTAPI
H2ProtectionToString(
    _In_ ULONG MemoryProtection
)
{
    switch (MemoryProtection & 0xFF)
    {
        case PAGE_NOACCESS:
            return L"NA";
        case PAGE_READONLY:
            return L"R";
        case PAGE_READWRITE:
            return L"RW";
        case PAGE_WRITECOPY:
            return L"WC";
        case PAGE_EXECUTE:
            return L"X";
        case PAGE_EXECUTE_READ:
            return L"RX";
        case PAGE_EXECUTE_READWRITE:
            return L"RWX";
        case PAGE_EXECUTE_WRITECOPY:
            return L"WCX";
        default:
            return L"???";
    }
}

NTSTATUS
NTAPI
H2QueryShortNameMappedFile(
    _In_ HANDLE Process,
    _In_ PVOID Address,
    _Out_ UNICODE_STRING* ShortName
)
{
    NTSTATUS status;
    PUNICODE_STRING buffer;
    SIZE_T bufferSize = RtlGetLongestNtPathLength() * sizeof(WCHAR);

    do
    {
        buffer = RtlAllocateHeap(RtlGetCurrentPeb()->ProcessHeap, 0, bufferSize);

        if (!buffer)
            return STATUS_NO_MEMORY;

        status = NtQueryVirtualMemory(
            Process,
            Address,
            MemoryMappedFilenameInformation,
            buffer,
            bufferSize,
            &bufferSize
        );

        if (!NT_SUCCESS(status))
            RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, buffer);
        else
            break;

    } while (status == STATUS_BUFFER_OVERFLOW);

    if (!NT_SUCCESS(status))
        return status;

    // Extract the filename only
    USHORT nameStart = 0;
    USHORT nameLength = buffer->Length;

    if (buffer->Length > sizeof(WCHAR))
    {
        for (USHORT i = buffer->Length / sizeof(WCHAR) - 1; i > 0; i--)
        {
            if (buffer->Buffer[i] == OBJ_NAME_PATH_SEPARATOR)
            {
                nameStart = i + 1;
                nameLength = buffer->Length - nameStart * sizeof(WCHAR);
                break;
            }
        }
    }

    // Copy it
    UNICODE_STRING name;
    name.Length = nameLength;
    name.MaximumLength = nameLength;
    name.Buffer = RtlAllocateHeap(RtlGetCurrentPeb()->ProcessHeap, 0, nameLength);

    if (name.Buffer)
    {
        memmove(name.Buffer, &buffer->Buffer[nameStart], name.Length);
        *ShortName = name;
    }
    else
    {
        status = STATUS_NO_MEMORY;
    }

    RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, buffer);
    return status;
}

// Not the actual structure, but has the same size.
typedef struct _HEAP_ENTRY
{
    PVOID Data1;
    PVOID Data2;
} HEAP_ENTRY, *PHEAP_ENTRY;

#define HEAP_SEGMENT_SIGNATURE 0xffeeffee

typedef struct _HEAP_SEGMENT
{
    HEAP_ENTRY Entry;
    ULONG SegmentSignature;
    ULONG SegmentFlags;
    LIST_ENTRY SegmentListEntry;
    union _HEAP *Heap;
    PVOID BaseAddress;
    ULONG NumberOfPages;
    PHEAP_ENTRY FirstEntry;
    PHEAP_ENTRY LastValidEntry;
    ULONG NumberOfUnCommittedPages;
    ULONG NumberOfUnCommittedRanges;
    USHORT SegmentAllocatorBackTraceIndex;
    USHORT Reserved;
    LIST_ENTRY UCRSegmentList;
} HEAP_SEGMENT, *PHEAP_SEGMENT;

#define HEAP_SIGNATURE 0xeeffeeff

typedef union _HEAP
{
    struct
    {
        HEAP_SEGMENT Segment;
        ULONG Flags;
        ULONG ForceFlags;
        ULONG CompatibilityFlags;
        ULONG EncodeFlagMask;
        HEAP_ENTRY Encoding;
        ULONG_PTR PointerKey; // Windows 7 only
        ULONG Interceptor;
        ULONG VirtualMemoryThreshold;
        ULONG Signature;
        // ...
    } Old; // Windows 7

    struct
    {
        HEAP_SEGMENT Segment;
        ULONG Flags;
        ULONG ForceFlags;
        ULONG CompatibilityFlags;
        ULONG EncodeFlagMask;
        HEAP_ENTRY Encoding;
        ULONG Interceptor;
        ULONG VirtualMemoryThreshold;
        ULONG Signature;
        // ...
    } New; // Windows 8+
} HEAP, *PHEAP;

#define SEGMENT_HEAP_SIGNATURE 0xddeeddee

typedef struct _SEGMENT_HEAP
{
    ULONG_PTR Padding[2];
    ULONG Signature;
    ULONG GlobalFlags;
    // ...
} SEGMENT_HEAP, PSEGMENT_HEAP;

typedef struct _HEAP_ENTRY32
{
    WOW64_POINTER(PVOID) Data1;
    WOW64_POINTER(PVOID) Data2;
} HEAP_ENTRY32, *PHEAP_ENTRY32;

typedef struct _HEAP_SEGMENT32
{
    HEAP_ENTRY32 HeapEntry;
    ULONG SegmentSignature;
    ULONG SegmentFlags;
    LIST_ENTRY32 SegmentListEntry;
    WOW64_POINTER(struct _HEAP32 *) Heap;
    WOW64_POINTER(PVOID) BaseAddress;
    ULONG NumberOfPages;
    WOW64_POINTER(PHEAP_ENTRY32) FirstEntry;
    WOW64_POINTER(PHEAP_ENTRY32) LastValidEntry;
    ULONG NumberOfUnCommittedPages;
    ULONG NumberOfUnCommittedRanges;
    USHORT SegmentAllocatorBackTraceIndex;
    USHORT Reserved;
    LIST_ENTRY32 UCRSegmentList;
} HEAP_SEGMENT32, *PHEAP_SEGMENT32;

typedef union _HEAP32
{
    struct
    {
        HEAP_SEGMENT32 Segment;
        ULONG Flags;
        ULONG ForceFlags;
        ULONG CompatibilityFlags;
        ULONG EncodeFlagMask;
        HEAP_ENTRY32 Encoding;
        WOW64_POINTER(ULONG_PTR) PointerKey;
        ULONG Interceptor;
        ULONG VirtualMemoryThreshold;
        ULONG Signature;
        // ...
    } Old; // Windows 7

    struct
    {
        HEAP_SEGMENT32 Segment;
        ULONG Flags;
        ULONG ForceFlags;
        ULONG CompatibilityFlags;
        ULONG EncodeFlagMask;
        HEAP_ENTRY32 Encoding;
        ULONG Interceptor;
        ULONG VirtualMemoryThreshold;
        ULONG Signature;
        // ...
    } New; // Windows 8+
} HEAP32, *PHEAP32;

typedef struct _SEGMENT_HEAP32
{
    WOW64_POINTER(ULONG_PTR) Padding[2];
    ULONG Signature;
    ULONG GlobalFlags;
    // ...
} SEGMENT_HEAP32, PSEGMENT_HEAP32;

typedef union _H2_ANY_HEAP
{
    HEAP Heap;
    HEAP32 Heap32;
    SEGMENT_HEAP SegmentHeap;
    SEGMENT_HEAP32 SegmentHeap32;
} H2_ANY_HEAP;

__success(return)
BOOLEAN
NTAPI
H2QueryClassHeap(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID Address,
    _In_ BOOLEAN WoW64,
    _Out_ PULONG HeapClass
)
{
    NTSTATUS status;
    H2_ANY_HEAP buffer;

    status = NtReadVirtualMemory(ProcessHandle, Address, &buffer, sizeof(buffer), NULL);

    if (!NT_SUCCESS(status))
        return FALSE;

    if (RtlGetCurrentPeb()->OSMajorVersion == 6 && RtlGetCurrentPeb()->OSMinorVersion == 1)
    {
        // Windows 7

        if (WoW64)
        {
            if (buffer.Heap32.Old.Signature == HEAP_SIGNATURE)
            {
                *HeapClass = buffer.Heap32.Old.Flags & HEAP_CLASS_MASK;
                return TRUE;
            }
        }
        else
        {
            if (buffer.Heap.Old.Signature == HEAP_SIGNATURE)
            {
                *HeapClass = buffer.Heap.Old.Flags & HEAP_CLASS_MASK;
                return TRUE;
            }
        }        
    }
    else
    {
        // Windows 8+

        if (WoW64)
        {
            if (buffer.Heap32.New.Signature == HEAP_SIGNATURE)
            {
                *HeapClass = buffer.Heap32.New.Flags & HEAP_CLASS_MASK;
                return TRUE;
            }
            else if (buffer.SegmentHeap32.Signature == SEGMENT_HEAP_SIGNATURE)
            {
                *HeapClass = buffer.SegmentHeap32.GlobalFlags & HEAP_CLASS_MASK;
                return TRUE;
            }
        }
        else
        {
            if (buffer.Heap.New.Signature == HEAP_SIGNATURE)
            {
                *HeapClass = buffer.Heap.New.Flags & HEAP_CLASS_MASK;
                return TRUE;
            }
            else if (buffer.SegmentHeap.Signature == SEGMENT_HEAP_SIGNATURE)
            {
                *HeapClass = buffer.SegmentHeap.GlobalFlags & HEAP_CLASS_MASK;
                return TRUE;
            }
        }
    }

    return FALSE;
}

PCWSTR
NTAPI
H2HeapClassToString(
    _In_ ULONG HeapClass
)
{
    switch (HeapClass)
    {
        case HEAP_CLASS_0:
            return L"Process";
        case HEAP_CLASS_1:
            return L"Private";
        case HEAP_CLASS_2:
            return L"Kernel";
        case HEAP_CLASS_3:
            return L"GDI";
        case HEAP_CLASS_4:
            return L"User";
        case HEAP_CLASS_5:
            return L"Console";
        case HEAP_CLASS_6:
            return L"User desktop";
        case HEAP_CLASS_7:
            return L"CSR shared";
        case HEAP_CLASS_8:
            return L"CSR port";
        default:
            return L"Unknown";
    }
}

BOOLEAN
NTAPI
H2ReportStatus(
    _In_ PCWSTR LastCall,
    _In_ NTSTATUS Status
)
{
    if (NT_SUCCESS(Status))
        return TRUE;

    UNICODE_STRING description;
    RtlInitUnicodeString(&description, L"Unknown error");

    // Find ntdll
    PLDR_DATA_TABLE_ENTRY ntdllLdrEntry = CONTAINING_RECORD(
        NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InInitializationOrderModuleList.Flink,
        LDR_DATA_TABLE_ENTRY,
        InInitializationOrderLinks
    );

    // Lookup the error description
    PMESSAGE_RESOURCE_ENTRY messageEntry;

    NTSTATUS status = RtlFindMessage(
        ntdllLdrEntry->DllBase,
        (ULONG)(ULONG_PTR)RT_MESSAGETABLE,
        0,
        NT_NTWIN32(Status) ? WIN32_FROM_NTSTATUS(Status) : (ULONG)Status,
        &messageEntry
    );

    if (NT_SUCCESS(status) && messageEntry->Flags & MESSAGE_RESOURCE_UNICODE)
    {
        RtlInitUnicodeString(&description, (PCWSTR)messageEntry->Text);

        // Trim the trailing new lines
        while (description.Length > 2 * sizeof(WCHAR) &&
            description.Buffer[description.Length / sizeof(WCHAR) - 1] == L'\n' &&
            description.Buffer[description.Length / sizeof(WCHAR) - 2] == L'\r')
            description.Length -= 2 * sizeof(WCHAR);
    }

    wprintf_s(L"ERROR: %s failed with 0x%X - %wZ\r\n", LastCall, Status, &description);
    return FALSE;
}
