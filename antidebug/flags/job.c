#include "job.h"
#include "..\core\syscall.h"

static inline DWORD __readprocid()
{
    const PBYTE teb = (PBYTE)__readgsqword(0x30);
    return (DWORD)(*(ULONG_PTR*)(teb + 0x40));
}

bool __adbg_process_job()
{
    bool problem = false;
    DWORD job_process_struct_size = sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + sizeof(ULONG_PTR) * 1024;
    JOBOBJECT_BASIC_PROCESS_ID_LIST* job_process_id_list = (JOBOBJECT_BASIC_PROCESS_ID_LIST*)(malloc(job_process_struct_size));

    if (job_process_id_list) {
        RtlSecureZeroMemory(job_process_id_list, job_process_struct_size);

        job_process_id_list->NumberOfProcessIdsInList = 1024;

        if (DbgNtQueryInformationJobObject(NULL, JobObjectBasicProcessIdList, job_process_id_list, job_process_struct_size, NULL)) {
            DWORD ok_processes = 0;
            for (DWORD i = 0; i < job_process_id_list->NumberOfAssignedProcesses; i++) {
                ULONG_PTR process_id = job_process_id_list->ProcessIdList[i];

                if (process_id == (ULONG_PTR)__readprocid()) {
                    ok_processes++;
                }
                else {
                    HANDLE job_process_handle = NULL;
                    OBJECT_ATTRIBUTES object_attributes = { 0 };
                    CLIENT_ID client_id = { 0 };
                    client_id.UniqueProcess = (HANDLE)process_id;

                    InitializeObjectAttributes(&object_attributes, NULL, 0, NULL, NULL);
                    NTSTATUS status = DbgNtOpenProcess(&job_process_handle, PROCESS_QUERY_INFORMATION, &object_attributes, &client_id);
                    if (!((NTSTATUS)(status) >= 0)) {
                        return false;
                    }

                    const int process_name_buffer_size = 4096;
                    PUNICODE_STRING process_name = (PUNICODE_STRING)(malloc(process_name_buffer_size));

                    if (process_name) {
                        SecureZeroMemory(process_name, process_name_buffer_size);

                        if (job_process_handle) {
                            ULONG return_length = 0;
                            status = DbgNtQueryInformationProcess(
                                job_process_handle,
                                (PROCESSINFOCLASS)ProcessImageFileName,
                                process_name,
                                process_name_buffer_size,
                                &return_length
                            );

                            if (NT_SUCCESS(status) && process_name->Buffer) {
                                const wchar_t* target = L"\\Windows\\System32\\conhost.exe";
                                const size_t target_len = wcslen(target) * sizeof(wchar_t);

                                if (process_name->Length >= target_len) {
                                    const wchar_t* buffer = process_name->Buffer;
                                    const size_t max_chars = process_name->Length / sizeof(wchar_t);
                                    const size_t target_chars = target_len / sizeof(wchar_t);

                                    for (i = 0; i <= max_chars - target_chars; i++) {
                                        if (memcmp(&buffer[i], target, target_len) == 0) {
                                            ok_processes++;
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        free(process_name);
                    }
                    DbgNtClose(job_process_handle);

                }
            }

            problem = ok_processes != job_process_id_list->NumberOfAssignedProcesses;
        }

        free(job_process_id_list);
    }

    return problem;
}