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

int wmain(int argc, wchar_t* argv[])
{
    NTSTATUS status;
    RTL_USER_PROCESS_INFORMATION processInfo;

    wprintf_s(L"Demo for Process Cloning via RtlCloneUserProcess by Hunt & Hackett.\r\n\r\n");
    wprintf_s(L"Hello from the parent! My PID is %zd, TID is %zd\r\n",
        (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess,
        (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread
    );

    status = RtlCloneUserProcess(
        RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES,
        NULL,
        NULL,
        NULL,
        &processInfo
    );

    if (status == STATUS_PROCESS_CLONED)
    {
        // Executing inside the clone...

        // Re-attach to the parent's console to be able to write to it
        FreeConsole();
        AttachConsole(ATTACH_PARENT_PROCESS);

        wprintf_s(L"Hello from the clone! My PID is %zd, TID is %zd\r\n",
            (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess,
            (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread
        );

        // Terminate without clean-up
        NtTerminateProcess(NtCurrentProcess(), STATUS_PROCESS_CLONED);
    }
    else
    {
        // Executing inside the original (parent) process...

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"Failed to clone the current process: 0x%x\r\n", status);
            return status;
        }

        status = NtWaitForSingleObject(processInfo.ProcessHandle, FALSE, NULL);

        // Save exit code before closing the process handle
        DWORD exitCode;
        GetExitCodeProcess(processInfo.ProcessHandle, &exitCode);

        NtClose(processInfo.ProcessHandle);
        NtClose(processInfo.ThreadHandle);

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"Failed to wait for the clone: 0x%x\r\n", status);
            return status;
        }

        if (!NT_SUCCESS(exitCode))
        {
            wprintf_s(L"Clone exit with error: 0x%x\r\n", exitCode);
            return exitCode;
        }

        wprintf_s(L"The clone exited.\r\n");
    }

    return STATUS_SUCCESS;
}
