/*
 * Copyright (c) 2023 Hunt & Hackett.
 *
 * This file is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include <cloning.h>

/* Handle inheritance */

// Snapshot current handle values and attributes
NTSTATUS 
NTAPI
H2CaptureHandleAttributes(
    _Outptr_ PH2_HANDLE_SNAPSHOT *Snapshot
)
{
    NTSTATUS status;
    PH2_HANDLE_SNAPSHOT snapshot = NULL;
    SIZE_T snapshotSize;

    if (RtlGetCurrentPeb()->OSMajorVersion > 6 ||
        (RtlGetCurrentPeb()->OSMajorVersion == 6 &&
            RtlGetCurrentPeb()->OSMinorVersion > 6))
    {
        // Windows 8+ supports enumerating per-process handles

        PPROCESS_HANDLE_SNAPSHOT_INFORMATION buffer;
        ULONG bufferSize = 0x800; // 2 KiB to start with

        do
        {
            buffer = RtlAllocateHeap(RtlGetCurrentPeb()->ProcessHeap, 0, bufferSize);

            if (!buffer)
                return STATUS_NO_MEMORY;

            status = NtQueryInformationProcess(
                NtCurrentProcess(),
                ProcessHandleInformation,
                buffer,
                bufferSize,
                &bufferSize
            );

            if (!NT_SUCCESS(status))
                RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, buffer);

        } while (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW);

        if (!NT_SUCCESS(status))
            return status;

        // Allocate the snapshot
        snapshotSize = sizeof(H2_HANDLE_SNAPSHOT) + 
            sizeof(H2_HANDLE_ENTRY) * (buffer->NumberOfHandles - 1);

        snapshot = RtlAllocateHeap(RtlGetCurrentPeb()->ProcessHeap, 0, snapshotSize);

        if (snapshot)
        {
            // Save handle attributes
            snapshot->NumberOfHandles = buffer->NumberOfHandles;

            for (ULONG_PTR i = 0; i < buffer->NumberOfHandles; i++)
            {
                snapshot->Handles[i].HandleValue = buffer->Handles[i].HandleValue;
                snapshot->Handles[i].HandleAttributes = buffer->Handles[i].HandleAttributes;
                snapshot->Handles[i].GrantedAccess = buffer->Handles[i].GrantedAccess;
                snapshot->Handles[i].ObjectTypeIndex = buffer->Handles[i].ObjectTypeIndex;
            }
        }

        RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, buffer);
    }
    else
    {
        // Windows 7 requires enumerating all system handles

        PSYSTEM_HANDLE_INFORMATION_EX buffer;
        ULONG bufferSize = 0x400000; // 4 MiB to start with

        do
        {
            buffer = RtlAllocateHeap(RtlGetCurrentPeb()->ProcessHeap, 0, bufferSize);

            if (!buffer)
                return STATUS_NO_MEMORY;

            status = NtQuerySystemInformation(
                SystemExtendedHandleInformation,
                buffer,
                bufferSize,
                &bufferSize
            );

            if (!NT_SUCCESS(status))
                RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, buffer);

        } while (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW);

        if (!NT_SUCCESS(status))
            return status;

        // Count our handles
        ULONG_PTR numberOfHandles = 0;

        for (ULONG_PTR i = 0; i < buffer->NumberOfHandles; i++)
        {
            if (buffer->Handles[i].UniqueProcessId == (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess)
                numberOfHandles++;
        }

        // Allocate the snapshot
        snapshotSize = sizeof(H2_HANDLE_SNAPSHOT) +
            sizeof(H2_HANDLE_ENTRY) * (numberOfHandles - 1);

        snapshot = RtlAllocateHeap(RtlGetCurrentPeb()->ProcessHeap, 0, snapshotSize);

        if (snapshot)
        {
            // Save handle attributes
            snapshot->NumberOfHandles = numberOfHandles;

            ULONG_PTR j = 0;
            for (ULONG_PTR i = 0; i < buffer->NumberOfHandles; i++)
            {
                if (buffer->Handles[i].UniqueProcessId == (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess)
                {
                    snapshot->Handles[j].HandleValue = (HANDLE)buffer->Handles[i].HandleValue;
                    snapshot->Handles[j].HandleAttributes = buffer->Handles[i].HandleAttributes;
                    snapshot->Handles[j].GrantedAccess = buffer->Handles[i].GrantedAccess;
                    snapshot->Handles[j].ObjectTypeIndex = buffer->Handles[i].ObjectTypeIndex;
                    j++;
                }
            }
        }

        RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, buffer);
    }

    if (!snapshot)
        return STATUS_NO_MEMORY;

    *Snapshot = snapshot;
    return STATUS_SUCCESS;
}

// Adjust inheritance for a set of handles
VOID
NTAPI
H2SetInheritanceHandles(
    _In_reads_(NumberOfHandles) PH2_HANDLE_ENTRY Handles,
    _In_ ULONG_PTR NumberOfHandles,
    _In_ H2_INHERITACE_OPERATION Operation
)
{
    OBJECT_HANDLE_FLAG_INFORMATION handleFlags = { 0 };

    switch (Operation)
    {
        case H2InheritanceEnable:
            handleFlags.Inherit = TRUE;
            break;

        case H2InheritanceDisable:
            handleFlags.Inherit = FALSE;
            break;

        case H2InheritanceRestore:
            break;

        default:
            return;
    }

    for (ULONG_PTR i = 0; i < NumberOfHandles; i++)
    {
        if (Operation == H2InheritanceRestore)
            handleFlags.Inherit = Handles[i].HandleAttributes & OBJ_INHERIT;
        
        handleFlags.ProtectFromClose = Handles[i].HandleAttributes & OBJ_PROTECT_CLOSE;

        NtSetInformationObject(
            Handles[i].HandleValue,
            ObjectHandleFlagInformation,
            &handleFlags,
            sizeof(handleFlags)
        );
    }
}

VOID
NTAPI
H2ReleaseHandleAttributes(
    _Frees_ptr_ PH2_HANDLE_SNAPSHOT Snapshot
)
{
    RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, Snapshot);
}

/* Shared memory */

// Allocate a shared memory region for communicating with the clone
NTSTATUS
NTAPI
H2MapSharedMamory(
    _Outptr_ PVOID *BaseAddress,
    _In_ SIZE_T AllocationSize,
    _Out_opt_ SIZE_T *ReturnedSize
)
{
    NTSTATUS status;
    HANDLE hSection;
    PVOID baseAddress;
    LARGE_INTEGER maximumSize;
    SIZE_T viewSize;

    // Prepare a pagefile-backed section object
    maximumSize.QuadPart = AllocationSize;

    status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &maximumSize,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL
    );

    if (!NT_SUCCESS(status))
        return status;

    // Map it for sharing
    baseAddress = NULL;
    viewSize = 0;

    status = NtMapViewOfSection(
        hSection,
        NtCurrentProcess(),
        &baseAddress,
        0,
        0,
        NULL,
        &viewSize,
        ViewShare,
        0,
        PAGE_READWRITE
    );

    NtClose(hSection);

    *BaseAddress = baseAddress;

    if (ReturnedSize)
        *ReturnedSize = viewSize;

    return status;
}

// Free a shared memory region
NTSTATUS
NTAPI
H2UnmapSharedMamory(
    _In_ PVOID BaseAddress
)
{
    return NtUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
}

/* Cloning */

// Attach the clone to the console of the parent process
BOOL
WINAPI
H2AttachToParentConsole(
    VOID
)
{
    return FreeConsole() && AttachConsole(ATTACH_PARENT_PROCESS);
}

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
)
{
    NTSTATUS status;
    BOOLEAN timedOut = FALSE;
    HANDLE hJob = NULL;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobLimits = { 0 };
    PH2_HANDLE_SNAPSHOT handleSnapshot = NULL;
    RTL_USER_PROCESS_INFORMATION processInfo = { 0 };

    // Snapshot all handles so we can make them inheritable
    if (Flags & H2_CLONE_PROCESS_FLAGS_INHERIT_ALL_HANDLES)
    {
        status = H2CaptureHandleAttributes(&handleSnapshot);

        if (!NT_SUCCESS(status))
            goto CLEANUP;
    }

    // Create a job to put the cloned process into
    status = NtCreateJobObject(
        &hJob,
        JOB_OBJECT_ALL_ACCESS,
        NULL
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Make sure it terminates on unexpected errors or if the parent exits.
    // Note that we snapshotted handles for inheritance before creating the job, so
    // it won't prolong clone's lifetime.
    jobLimits.BasicLimitInformation.LimitFlags = 
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | 
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
        JOB_OBJECT_LIMIT_BREAKAWAY_OK;

    status = NtSetInformationJobObject(
        hJob,
        JobObjectExtendedLimitInformation,
        &jobLimits,
        sizeof(jobLimits)
    );

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    if (Flags & H2_CLONE_PROCESS_FLAGS_INHERIT_ALL_HANDLES)
    {
        // Enable inheritance for all handles
        H2SetInheritanceHandles(
            handleSnapshot->Handles,
            handleSnapshot->NumberOfHandles,
            H2InheritanceEnable
        );
    }

    // NOTE: when debugging, do not single-step over RtlCloneUserProcess 
    // because it inserts a breakpoint (int 3) that will be copied
    // to the clone, preventing it from executing the callback.

    // Clone the current process
    status = RtlCloneUserProcess(
        RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED | 
            (Flags & (H2_CLONE_PROCESS_FLAGS_INHERIT_HANDLES | H2_CLONE_PROCESS_FLAGS_INHERIT_ALL_HANDLES) ?
                RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES : 0),
        NULL,
        NULL,
        NULL,
        &processInfo
    );

    if (status == STATUS_PROCESS_CLONED)
    {
        // Execute the callback in the clone...

        status = STATUS_UNHANDLED_EXCEPTION;

        __try
        {
            #pragma warning(suppress: 6387) // Argument may be NULL
            status = Callback(Argument);
        }
        __finally
        {
            NtTerminateProcess(NtCurrentProcess(), status);
        }
    }

    // Executing in the parent...

    if (Flags & H2_CLONE_PROCESS_FLAGS_INHERIT_ALL_HANDLES)
    {
        // Restore handle inheritance
        H2SetInheritanceHandles(
            handleSnapshot->Handles,
            handleSnapshot->NumberOfHandles,
            H2InheritanceRestore
        );
    }

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Try to put the clone into the job, but don't fail if we can't
    // (which might happen on Windows 7, before nested jobs support)
    NtAssignProcessToJobObject(hJob, processInfo.ProcessHandle);

    // Replace the primary token, if necessary
    if (TokenHandle)
    {
        PROCESS_ACCESS_TOKEN tokenInfo;

        memset(&tokenInfo, 0, sizeof(tokenInfo));
        tokenInfo.Token = TokenHandle;

        status = NtSetInformationProcess(
            processInfo.ProcessHandle, 
            ProcessAccessToken,
            &tokenInfo,
            sizeof(tokenInfo)
        );

        if (!NT_SUCCESS(status))
            goto CLEANUP;
    }

    // Let the clone run
    status = NtResumeThread(processInfo.ThreadHandle, NULL);

    if (!NT_SUCCESS(status))
        goto CLEANUP;
    
    do
    {
        // Wait for completion
        status = NtWaitForSingleObject(processInfo.ProcessHandle, Alertable, Timeout);
    } while (status == STATUS_USER_APC || status == STATUS_ALERTED);

    if (!NT_SUCCESS(status))
        goto CLEANUP;

    // Terminate the clone on timeout
    if (status == STATUS_TIMEOUT)
    {
        timedOut = TRUE;
        NtTerminateProcess(processInfo.ProcessHandle, STATUS_TIMEOUT);
    }

    // Forward the result status to the caller
    if (CompletionStatus)
    {
        PROCESS_BASIC_INFORMATION basicInfo;

        status = NtQueryInformationProcess(
            processInfo.ProcessHandle, 
            ProcessBasicInformation, 
            &basicInfo, 
            sizeof(basicInfo), 
            NULL
        );

        if (!NT_SUCCESS(status))
            goto CLEANUP;

        *CompletionStatus = basicInfo.ExitStatus;
    }

    if (timedOut)
        status = STATUS_TIMEOUT;

CLEANUP:
    if (hJob)
    {
        NtTerminateJobObject(hJob, STATUS_CANCELLED);
        NtClose(hJob);
    }

    if (processInfo.ProcessHandle)
    {
        NtTerminateProcess(processInfo.ProcessHandle, STATUS_CANCELLED);
        NtClose(processInfo.ProcessHandle);
    }

    if (processInfo.ThreadHandle)
        NtClose(processInfo.ThreadHandle);

    if (handleSnapshot)
        H2ReleaseHandleAttributes(handleSnapshot);

    return status;
}
