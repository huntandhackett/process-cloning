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
#include <minidumpapiset.h>

typedef enum _H2_CLONING_MODE {
    H2CloneViaReflection = 1,
    H2CloneViaNativeApi
} H2_CLONING_MODE;

#define H2_ARGV_MODE_INDEX 1
#define H2_ARGV_PID_INDEX 2
#define H2_ARGV_FILENAME_INDEX 3

// Report progress on a specific operation to the console
BOOLEAN H2ReportStatus(
    _In_ PCWSTR Location,
    _In_ PCWSTR LastCall,
    _In_ NTSTATUS Status
)
{
    if (NT_SUCCESS(Status))
        wprintf_s(L"%s: Success\r\n", Location);
    else
    {
        PVOID dllBase;
        UNICODE_STRING dllName;
        UNICODE_STRING description;

        RtlInitUnicodeString(&description, L"Unknown error");

        // Choose the DLL to look up the error description
        RtlInitUnicodeString(&dllName, NT_NTWIN32(Status) ? L"kernel32.dll" : L"ntdll.dll");
        NTSTATUS status = LdrGetDllHandle(NULL, NULL, &dllName, &dllBase);
        
        if (NT_SUCCESS(status))
        {
            PMESSAGE_RESOURCE_ENTRY messageEntry;
            
            // Lookup the error description
            status = RtlFindMessage(
                dllBase,
                (ULONG)(ULONG_PTR)RT_MESSAGETABLE,
                0,
                NT_NTWIN32(Status) ? WIN32_FROM_NTSTATUS(Status) : (ULONG)Status,
                &messageEntry
            );

            if (NT_SUCCESS(status) && messageEntry->Flags & MESSAGE_RESOURCE_UNICODE)
                RtlInitUnicodeString(&description, (PCWSTR)messageEntry->Text);
        }

        // Trim the trailing new line
        if (description.Length > 2 * sizeof(WCHAR) &&
            description.Buffer[description.Length / sizeof(WCHAR) - 1] == L'\n' &&
            description.Buffer[description.Length / sizeof(WCHAR) - 2] == L'\r')
            description.Length -= 2 * sizeof(WCHAR);

        wprintf_s(L"%s: 0x%X at %s - %wZ\r\n", Location, Status, LastCall, &description);
    }

    return NT_SUCCESS(Status);
}

int wmain(int argc, wchar_t* argv[])
{
    NTSTATUS status;
    H2_CLONING_MODE mode;
    UNICODE_STRING fileName = { 0 };
    HANDLE hParentProcess = NULL;
    HANDLE hCloneProcess = NULL;
    HANDLE hFile = NULL;

    wprintf_s(L"Demo for dumping process memory via cloning by Hunt & Hackett.\r\n\r\n");

    if (argc < 4)
    {
        wprintf_s(L"Usage: CloneAndMinidump.exe [Mode] [PID] [Filename]\r\n\r\n");
        wprintf_s(L"Supported modes:\r\n");
        wprintf_s(L"  -r - clone via RtlCreateProcessReflection\r\n");
        wprintf_s(L"  -p - clone via NtCreateProcessEx\r\n");

        return STATUS_INVALID_PARAMETER;
    }

    if (wcscmp(argv[H2_ARGV_MODE_INDEX], L"-r") == 0)
        mode = H2CloneViaReflection;
    else if (wcscmp(argv[H2_ARGV_MODE_INDEX], L"-p") == 0)
        mode = H2CloneViaNativeApi;
    else
    {
        wprintf(L"Error: urecognized mode specified.\r\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Enable the Debug privilege when possible
    BOOLEAN wasDebugEnabled;
    status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &wasDebugEnabled);

    H2ReportStatus(L"1. Enabling the debug privilege", L"RtlAdjustPrivilege", status);

    // Open the target process for cloning
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;
    
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)wcstoul(argv[H2_ARGV_PID_INDEX], NULL, 0);
    clientId.UniqueThread = NULL;

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    status = NtOpenProcess(
        &hParentProcess,
        mode == H2CloneViaReflection ? 
            PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE :
            PROCESS_CREATE_PROCESS,
        &objAttr,
        &clientId
    );

    if (!H2ReportStatus(L"2. Opening the target process", L"NtOpenProcess", status))
        goto CLEANUP;

    // Clone the target process
    switch (mode)
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

                if (!H2ReportStatus(L"3. Cloning the target process", L"RtlCreateProcessReflection", status))
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
                    PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    &objAttr,
                    hParentProcess,
                    0,
                    NULL,
                    NULL,
                    NULL,
                    0
                );

                if (!H2ReportStatus(L"3. Cloning the target process", L"NtCreateProcessEx", status))
                    goto CLEANUP;
            }
            break;
    }

    NtClose(hParentProcess);
    hParentProcess = NULL;
    
    // Convert the filename to NT format
    status = RtlDosPathNameToNtPathName_U_WithStatus(
        argv[H2_ARGV_FILENAME_INDEX],
        &fileName,
        NULL,
        NULL
    );

    if (!H2ReportStatus(L"4. Preparing the filename", L"RtlDosPathNameToNtPathName_U_WithStatus", status))
        goto CLEANUP;

    // Create the target file
    OBJECT_ATTRIBUTES objAttrib;
    IO_STATUS_BLOCK isb;

    InitializeObjectAttributes(&objAttrib, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateFile(
        &hFile,
        FILE_WRITE_DATA | DELETE | SYNCHRONIZE,
        &objAttrib,
        &isb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    RtlFreeUnicodeString(&fileName);
    memset(&fileName, 0, sizeof(fileName));

    if (!H2ReportStatus(L"5. Creating the file for minidump", L"NtCreateFile", status))
        goto CLEANUP;

    // Start dumping
    BOOL result = MiniDumpWriteDump(
        hCloneProcess,
        0,
        hFile,
        MiniDumpWithFullMemory,
        NULL,
        NULL,
        NULL
    );

    if (!H2ReportStatus(L"6. Writing the minidump", L"MiniDumpWriteDump", result ? STATUS_SUCCESS : NTSTATUS_FROM_WIN32(RtlGetLastWin32Error())))
        goto CLEANUP;

    NtClose(hFile);
    hFile = NULL;

    status = STATUS_SUCCESS;

CLEANUP:
    if (hParentProcess)
        NtClose(hParentProcess);

    if (hCloneProcess)
    {
        NtTerminateProcess(hCloneProcess, STATUS_PROCESS_CLONED);
        NtClose(hCloneProcess);
    }

    if (fileName.Buffer)
        RtlFreeUnicodeString(&fileName);

    if (hFile)
    {
        // Undo file creation on failure
        FILE_DISPOSITION_INFORMATION fileInfo;
        fileInfo.DeleteFile = TRUE;

        NtSetInformationFile(
            hFile,
            &isb,
            &fileInfo,
            sizeof(fileInfo),
            FileDispositionInformation
        );

        NtClose(hFile);
    }

    return status;
}
