/*
 * Copyright (c) 2023 Hunt & Hackett.
 *
 * This file is licensed under the MIT license.
 *
 * Authors:
 *     diversenok
 *
 */

#include <phnt_windows.h>
#include <phnt.h>
#include <stdio.h>
#include <cloning.h>

NTSTATUS
NTAPI
Payload(
    PVOID Parameter
)
{
    if (!H2AttachToParentConsole())
        return NTSTATUS_FROM_WIN32(GetLastError());

    wprintf_s(L"Hello from clone! My PID is: %zu\r\n", (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess);
    return STATUS_SUCCESS;
}

int wmain(int argc, wchar_t* argv[])
{   
    NTSTATUS status;
    NTSTATUS completionStatus;
    
    wprintf_s(L"Simple demo for Process Cloning by Hunt & Hackett.\r\n\r\n");
    wprintf_s(L"Hello from parent process! My PID is: %zu\r\n", (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess);

    // H2ExecuteInClone is a wrapper that clones the current process, 
    // executes the provided function there, waits for its completion, 
    // and, optionally, forwards the exit status. It also supports
    // inheriting all handles and using custom primary token for the 
    // new process.

    status = H2ExecuteInClone(
        H2_CLONE_PROCESS_FLAGS_INHERIT_ALL_HANDLES,
        NULL,
        Payload,
        NULL,
        &completionStatus,
        NULL,
        FALSE
    );

    if (!NT_SUCCESS(status))
    {
        wprintf_s(L"Unable to clone the current process: 0x%x\r\n", status);
        return status;
    }

    if (!NT_SUCCESS(completionStatus))
    {
        wprintf_s(L"Clone exited with error code: 0x%x\r\n", status);
        return status;
    }

    wprintf_s(L"Clone exited with a successful code.\r\n");
    return STATUS_SUCCESS;
}
