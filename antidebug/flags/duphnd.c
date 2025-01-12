#include "duphnd.h"

typedef enum _MYOBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation, 
	ObjectTypeInformation, 
	ObjectTypesInformation, 
	ObjectHandleFlagInformation, 
	ObjectSessionInformation,
	ObjectSessionObjectInformation,
	MaxObjectInfoClass
} MYOBJECT_INFORMATION_CLASS;

typedef struct _MYOBJECT_HANDLE_FLAG_INFORMATION
{
	BOOLEAN Inherit;
	BOOLEAN ProtectFromClose;
} MYOBJECT_HANDLE_FLAG_INFORMATION, * PMYOBJECT_HANDLE_FLAG_INFORMATION;

typedef NTSTATUS(WINAPI* fnNtSetInformationObject)(
	_In_ HANDLE Handle,
	_In_ MYOBJECT_INFORMATION_CLASS ObjectInformationClass,
	_In_ PVOID ObjectInformation,
	_In_ ULONG ObjectInformationLength
	);

bool DuplicatedHandles() {
	HANDLE processHandle1, processHandle2;
	const HANDLE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll) return TRUE;

	fnNtSetInformationObject pfnNtSetInformationObject = \
	(fnNtSetInformationObject)GetProcAddress(hNtdll, "ZwSetInformationObject");
	MYOBJECT_HANDLE_FLAG_INFORMATION objInfo = { 0 };
	objInfo.Inherit = false;
	objInfo.ProtectFromClose = true;

	__try {
		processHandle1 = GetCurrentProcess();
		DuplicateHandle(processHandle1, processHandle1, processHandle1, &processHandle2, 0, FALSE, 0);
		pfnNtSetInformationObject(processHandle2, ObjectHandleFlagInformation, &objInfo, sizeof(objInfo));
		DuplicateHandle(processHandle1, processHandle2, processHandle1, &processHandle2, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return TRUE;
	}

	return FALSE;
}