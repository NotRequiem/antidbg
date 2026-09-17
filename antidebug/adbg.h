#pragma once

#define WIN32_LEAN_AND_MEAN

#include "core\thrmng.h"
#include "core\guard.h"
#include "core\monitor.h"
#include "core\syscall.h"
#include "core\handler.h"
#include "core\debug.h"
#include "core\random.h"

#include "api\dbgpresent.h"
#include "api\rdbgpresent.h"
#include "api\dbgobjhandle.h"
#include "api\procdbgflag.h"
#include "api\procdbgport.h"
#include "api\sysdbgcontrol.h"
#include "api\setdbgfltstate.h"
#include "api\sysimpl.h"
#include "api\outdbgstring.h"

#include "asm\int2d.h"
#include "asm\int3.h"
#include "asm\ice.h"
#include "asm\prehop.h"
#include "asm\popf.h"
#include "asm\lbr_btf.h"
#include "asm\stckseg.h"
#include "asm\instcnt.h"

#include "exceptions\raiseexc.h"
#include "exceptions\pgexcbp.h"

#include "flags\kerneldbg.h"
#include "flags\ntglobalflag.h"
#include "flags\duphnd.h"
#include "flags\prntproc.h"
#include "flags\job.h"
#include "flags\timing.h"
#include "flags\window.h"
#include "flags\crtlevent.h"
#include "flags\suspend.h"
#include "flags\race.h"
#include "flags\loadlib.h"

#include "memory\hwbreakp.h"
#include "memory\readstck.h"
#include "memory\peb.h"
#include "memory\vrtalloc.h"
#include "memory\membreak.h"
#include "memory\heap.h"
#include "memory\workset.h"
#include "memory\mapview.h"

#include "object\clshandle.h"
#include "object\dbgobj.h"
#include "object\opnproc.h"
#include "object\prothnd.h"
#include "object\device.h"

#ifdef __cplusplus
extern "C" {
#endif

    typedef enum {
        CHECK_VOID,
        CHECK_PROCESS,
        CHECK_THREAD,
        CHECK_PROCESS_THREAD
    } ADBG_CHECK_TYPE;

    typedef struct {
        ADBG_CHECK_TYPE type;
        const char* function_name;
        union {
            bool (*function_ptr)();
            bool (*function_with_process)(HANDLE);
            bool (*function_with_thread)(HANDLE);
            bool (*function_with_process_and_thread)(HANDLE, HANDLE);
        };
        bool result;
    } checks_info;

    extern checks_info debugger_checks[];

    void StartDebugProtection(); // guard mode
    bool isProgramBeingDebugged(); // single run mode

#ifdef __cplusplus
}
#endif