#pragma once

#include "core\thrmng.h"
#include "core\atcptr.h"
#include "core\hasher.h"
#include "core\syscall.h"
#include "core\handler.h"

#include "api\dbgpresent.h"
#include "api\rdbgpresent.h"
#include "api\dbgobjhandle.h"
#include "api\procdbgflag.h"
#include "api\procdbgport.h"

#include "asm\dbgbreak.h"
#include "asm\int2d.h"
#include "asm\int3.h"
#include "asm\sckreg.h"
#include "asm\prehop.h"
#include "asm\popf.h"

#include "exceptions\raiseexc.h"
#include "exceptions\hwbreakp2.h"
#include "exceptions\pgexcbp.h"

#include "flags\kerneldbg.h"
#include "flags\ntglobalflag.h"
#include "flags\prochpflag.h"
#include "flags\prochpforceflag.h"
#include "flags\duphnd.h"
#include "flags\prntproc.h"
#include "flags\ntldt.h"
#include "flags\job.h"
#include "flags\timing.h"
#include "flags\window.h"

#include "memory\hwbreakp.h"
#include "memory\readstck.h"
#include "memory\peb.h"
#include "memory\vrtalloc.h"
#include "memory\membreakp.h"

#include "object\clshandle.h"
#include "object\dbgobj.h"
#include "object\opnproc.h"
#include "object\prothnd.h"
#include "object\sysdbgctl.h"

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        bool result;
        const char* functionName;
        union {
            bool (*functionPtr)();
            bool (*functionPtrWithProcess)(HANDLE);
            bool (*functionPtrWithThread)(HANDLE);
            bool (*functionPtrWithProcessAndThread)(HANDLE, HANDLE);
        };
    } DebugCheckResult;

    extern DebugCheckResult debuggerChecks[];

    void StartDebugProtection(); // guard mode
    bool isProgramBeingDebugged(); // single run mode

#ifdef __cplusplus
}
#endif