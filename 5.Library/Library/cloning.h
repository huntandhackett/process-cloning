/*
 * Copyright (c) 2023 Hunt & Hackett.
 *
 * This file is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#ifndef _CLONING_H
#define _CLONING_H

#include <phnt_windows.h>
#include <phnt.h>

/* Handle inheritance */

typedef struct _H2_HANDLE_ENTRY {
    HANDLE HandleValue;
    ULONG HandleAttributes;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
} H2_HANDLE_ENTRY, *PH2_HANDLE_ENTRY;

typedef struct _H2_HANDLE_SNAPSHOT {
    ULONG_PTR NumberOfHandles;
    _Field_size_(NumberOfHandles) H2_HANDLE_ENTRY Handles[1];
} H2_HANDLE_SNAPSHOT, *PH2_HANDLE_SNAPSHOT;

typedef enum _H2_INHERITACE_OPERATION {
    H2InheritanceEnable = 1,
    H2InheritanceDisable,
    H2InheritanceRestore,
} H2_INHERITACE_OPERATION;

// Snapshot current handle values and attributes
NTSTATUS 
NTAPI
H2CaptureHandleAttributes(
    _Outptr_ PH2_HANDLE_SNAPSHOT *Snapshot
);

// Adjust inheritance for a set of handles
VOID
NTAPI
H2SetInheritanceHandles(
    _In_reads_(NumberOfHandles) PH2_HANDLE_ENTRY Handles,
    _In_ ULONG_PTR NumberOfHandles,
    _In_ H2_INHERITACE_OPERATION Operation
);

// Free the handle snapshot
VOID
NTAPI
H2ReleaseHandleAttributes(
    _Frees_ptr_ PH2_HANDLE_SNAPSHOT Snapshot
);

/* Shared memory */

// Allocate a shared memory region for communicating with the clone
NTSTATUS
NTAPI
H2MapSharedMamory(
    _Outptr_ PVOID *BaseAddress,
    _In_ SIZE_T AllocationSize,
    _Out_opt_ SIZE_T *ReturnedSize
);

// Free a shared memory region
NTSTATUS
NTAPI
H2UnmapSharedMamory(
    _In_ PVOID BaseAddress
);

/* Cloning */

// Attach the clone to the console of the parent process
BOOL
WINAPI
H2AttachToParentConsole(
    VOID
);

#define H2_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000001
#define H2_CLONE_PROCESS_FLAGS_INHERIT_ALL_HANDLES 0x00000002

// Execute a callback in a clone of the current process
NTSTATUS
NTAPI
H2ExecuteInClone(
    _In_ ULONG Flags,
    _In_opt_ HANDLE TokenHandle,
    _In_ PUSER_THREAD_START_ROUTINE Callback,
    _In_opt_ PVOID Argument,
    _Out_opt_ PNTSTATUS CompletionStatus,
    _In_opt_ PLARGE_INTEGER Timeout,
    _In_ BOOLEAN Alertable
);

#endif
