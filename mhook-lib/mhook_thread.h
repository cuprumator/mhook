#pragma once

#include "mhook_internal.h"

BOOL SuspendOtherThreads(HOOK_CONTEXT* hookCtx, int hookCount, void **freeCtx);
VOID ResumeOtherThreads(void *freeCtx);