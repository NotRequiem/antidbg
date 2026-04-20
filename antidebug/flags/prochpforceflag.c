#include "prochpforceflag.h"

static inline PUINT32 __read_heap() 
{
	PINT64 process_heap = NULL;
	PUINT32 heap_force_flags = NULL;
	process_heap = (PINT64)(__readgsqword(0x60) + 0x30);
	heap_force_flags = (PUINT32)(*process_heap + 0x74);

	return heap_force_flags;
}

bool __adbg_heap_forceflag() 
{
	PUINT32 heap_force_flags = NULL;

	heap_force_flags = __read_heap();

	if (*heap_force_flags > 0)
		return true;

	return false;
}
