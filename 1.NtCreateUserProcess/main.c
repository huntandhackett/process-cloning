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
    HANDLE hProcess;
    HANDLE hThread;

    wprintf_s(L"Demo for Process Cloning via NtCreateUserProcess by Hunt & Hackett.\r\n\r\n");
    wprintf_s(L"Hello from the parent! My PID is %zd, TID is %zd\r\n",
        (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess,
        (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread
    );

    PS_CREATE_INFO createInfo = { 0 };
    createInfo.Size = sizeof(createInfo);

    status = NtCreateUserProcess(
        &hProcess,
        &hThread,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        0,
        NULL,
        &createInfo,
        NULL
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

        status = NtWaitForSingleObject(hProcess, FALSE, NULL);

        NtClose(hProcess);
        NtClose(hThread);

        if (!NT_SUCCESS(status))
        {
            wprintf_s(L"Failed to wait for the clone: 0x%x\r\n", status);
            return status;
        }

        wprintf_s(L"The clone exited.\r\n");
    }

    return STATUS_SUCCESS;
}
