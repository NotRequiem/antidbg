#include "dbgobj.h"
#include "..\core\syscall.h"

bool CheckNtQueryObject()
{
	HANDLE DebugObjectHandle;
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	InitializeObjectAttributes(&ObjectAttributes, 0, 0, 0, 0);
	BYTE memory[0x1000] = { 0 };
	POBJECT_TYPE_INFORMATION ObjectInformation = (POBJECT_TYPE_INFORMATION)memory;
	NTSTATUS Status;

	DbgNtCreateDebugObject(&DebugObjectHandle, DEBUG_ALL_ACCESS, &ObjectAttributes, FALSE);

	Status = DbgNtQueryObject(DebugObjectHandle, ObjectTypeInformation, ObjectInformation, sizeof(memory), 0);

	DbgNtClose(DebugObjectHandle);

	if (Status >= 0)
	{
		if (ObjectInformation->TotalNumberOfObjects == 0)
			return TRUE;
		else
			return FALSE;
	}
	else
	{
		return FALSE;
	}
}