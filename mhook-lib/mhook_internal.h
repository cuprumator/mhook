#pragma once

#include <windows.h>
#include "mhook.h"
#include "../disasm-lib/disasm.h"

//=========================================================================
#define MHOOKS_MAX_CODE_BYTES	32
#define MHOOKS_MAX_RIPS			 4

//=========================================================================
// The trampoline structure - stores every bit of info about a hook
struct PAGE_INFO;
struct MHOOKS_TRAMPOLINE {
    PBYTE	pSystemFunction;			// the original system function
    DWORD	cbOverwrittenCode;			// number of bytes overwritten by the jump
    PBYTE	pHookFunction;				// the hook function that we provide
    BYTE	codeJumpToHookFunction[MHOOKS_MAX_CODE_BYTES];	// placeholder for code that jumps to the hook function
    BYTE	codeTrampoline[MHOOKS_MAX_CODE_BYTES];			// placeholder for code that holds the first few
    //   bytes from the system function and a jump to the remainder
    //   in the original location
    BYTE	codeUntouched[MHOOKS_MAX_CODE_BYTES];			// placeholder for unmodified original code
    //   (we patch IP-relative addressing)
    PAGE_INFO*  pPageInfo;
    BOOLEAN reserved;
};

//=========================================================================
// The page info structure - cache for pages
struct PAGE_INFO{
    DWORD counter;
    MHOOKS_TRAMPOLINE pTramplines[1];
};

//=========================================================================
// For debug and unit tests only
struct MHOOKUT_GlobalVars
{
    MHOOKS_TRAMPOLINE** Hooks;
    DWORD HooksInUse;
    PAGE_INFO** PagesCache;
    DWORD PageSize;
    DWORD TramplinesInPage;
};
void MHOOKUT_GetGlobalVars(MHOOKUT_GlobalVars * gv);
//=========================================================================

//=========================================================================
// The patch data structures - store info about rip-relative instructions
// during hook placement
struct MHOOKS_RIPINFO
{
    DWORD	dwOffset;
    S64		nDisplacement;
};

struct MHOOKS_PATCHDATA
{
    S64				nLimitUp;
    S64				nLimitDown;
    DWORD			nRipCnt;
    MHOOKS_RIPINFO	rips[MHOOKS_MAX_RIPS];
};

struct HOOK_CONTEXT
{
    PVOID pSystemFunction;
    PVOID pHookFunction;
    DWORD dwInstructionLength;
    MHOOKS_TRAMPOLINE* pTrampoline;

    MHOOKS_PATCHDATA patchdata;
};

//=========================================================================
#ifndef gle
#define gle GetLastError
#endif