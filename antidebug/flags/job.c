#include "job.h"
#include "..\core\syscall.h"

bool ProcessJob() {
    BOOL foundProblem = FALSE;
    DWORD jobProcessStructSize = sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + sizeof(ULONG_PTR) * 1024;
    JOBOBJECT_BASIC_PROCESS_ID_LIST* jobProcessIdList = (JOBOBJECT_BASIC_PROCESS_ID_LIST*)(malloc(jobProcessStructSize));

    if (jobProcessIdList) {
        SecureZeroMemory(jobProcessIdList, jobProcessStructSize);

        jobProcessIdList->NumberOfProcessIdsInList = 1024;

        if (DbgNtQueryInformationJobObject(NULL, JobObjectBasicProcessIdList, jobProcessIdList, jobProcessStructSize, NULL)) {
            DWORD ok_processes = 0;
            for (DWORD i = 0; i < jobProcessIdList->NumberOfAssignedProcesses; i++) {
                ULONG_PTR processId = jobProcessIdList->ProcessIdList[i];

                if (processId == (ULONG_PTR)GetCurrentProcessId()) {
                    ok_processes++;
                }
                else {
                    HANDLE hJobProcess = NULL;
                    OBJECT_ATTRIBUTES objAttr = { 0 };
                    CLIENT_ID clientId = { 0 };
                    clientId.UniqueProcess = (HANDLE)processId;

                    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
                    NTSTATUS status = DbgNtOpenProcess(&hJobProcess, PROCESS_QUERY_INFORMATION, &objAttr, &clientId);
                    if (!((NTSTATUS)(status) >= 0)) {
                        return false;
                    }

                    const int processNameBufferSize = 4096;
                    wchar_t* processName = (wchar_t*)(malloc(sizeof(wchar_t) * processNameBufferSize));
                    if (processName) {
                        SecureZeroMemory(processName, sizeof(wchar_t) * processNameBufferSize);

                        if(hJobProcess)
                        if (GetProcessImageFileNameW(hJobProcess, processName, processNameBufferSize) > 0) {
                            const wchar_t* target = L"\\Windows\\System32\\conhost.exe";

                            if (wcsstr(processName, target) != NULL) {
                                ok_processes++;
                            }
                        }

                        free(processName);
                    }
                    DbgNtClose(hJobProcess);

                }
            }

            foundProblem = ok_processes != jobProcessIdList->NumberOfAssignedProcesses;
        }

        free(jobProcessIdList);
    }

    return foundProblem;
}