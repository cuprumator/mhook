#include "mhook_thread.h"
#include "mhook_printf.h"
#include "ntdll.h"

//=========================================================================
#ifndef GOOD_HANDLE
#define GOOD_HANDLE(a) ((a!=INVALID_HANDLE_VALUE)&&(a!=NULL))
#endif

static DWORD g_nThreadHandles = 0;
static HANDLE* g_hThreadHandles = NULL;

//=========================================================================
// ZwQuerySystemInformation definitions
typedef NTSTATUS(NTAPI* PZwQuerySystemInformation)(
    __in       Nt::SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout    PVOID SystemInformation,
    __in       ULONG SystemInformationLength,
    __out_opt  PULONG ReturnLength
    );

#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)

static PZwQuerySystemInformation fnZwQuerySystemInformation = (PZwQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwQuerySystemInformation");

static BOOL VerifyThreadContext(PBYTE pIp, HOOK_CONTEXT* hookCtx, int hookCount)
{
    for (int i = 0; i < hookCount; i++)
    {
        if (pIp >= (PBYTE)hookCtx[i].pSystemFunction && pIp < ((PBYTE)hookCtx[i].pSystemFunction + hookCtx[i].dwInstructionLength))
        {
            return FALSE;
        }
    }

    return TRUE;
}

//=========================================================================
// Internal function:
//
// Suspend a given thread and try to make sure that its instruction
// pointer is not in the given range.
//=========================================================================
static HANDLE SuspendOneThreadEx(DWORD dwThreadId, HOOK_CONTEXT* hookCtx, int hookCount)
{
    // open the thread
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);

    if (GOOD_HANDLE(hThread))
    {
        // attempt suspension
        DWORD dwSuspendCount = SuspendThread(hThread);
        if (dwSuspendCount != -1)
        {
            // see where the IP is
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_CONTROL;
            int nTries = 0;
            while (GetThreadContext(hThread, &ctx))
            {
#ifdef _M_IX86
                PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Eip;
#elif defined _M_X64
                PBYTE pIp = (PBYTE)(DWORD_PTR)ctx.Rip;
#endif
                if (!VerifyThreadContext(pIp, hookCtx, hookCount))
                {
                    if (nTries < 3)
                    {
                        // oops - we should try to get the instruction pointer out of here. 
                        ODPRINTF((L"mhooks: SuspendOneThread: suspended thread %d - IP is at %p - IS COLLIDING WITH CODE", dwThreadId, pIp));
                        ResumeThread(hThread);
                        Sleep(100);
                        SuspendThread(hThread);
                        nTries++;
                    }
                    else
                    {
                        // we gave it all we could. (this will probably never 
                        // happen - unless the thread has already been suspended 
                        // to begin with)
                        ODPRINTF((L"mhooks: SuspendOneThread: suspended thread %d - IP is at %p - IS COLLIDING WITH CODE - CAN'T FIX", dwThreadId, pIp));
                        ResumeThread(hThread);
                        CloseHandle(hThread);
                        hThread = NULL;
                        break;
                    }
                }
                else
                {
                    // success, the IP is not conflicting
                    ODPRINTF((L"mhooks: SuspendOneThread: Successfully suspended thread %d - IP is at %p", dwThreadId, pIp));
                    break;
                }
            }
        }
        else
        {
            // couldn't suspend
            CloseHandle(hThread);
            hThread = NULL;
        }
    }

    return hThread;
}

// free memory allocated for processes snapshot
static VOID CloseProcessSnapshot(VOID* snapshotContext)
{
	free(snapshotContext);
}

//=========================================================================
// Internal function:
//
// Resumes all previously suspended threads in the current process.
//=========================================================================
VOID ResumeOtherThreads(void *freeCtx) {
    // go through our list
    for (DWORD i = 0; i < g_nThreadHandles; i++)
    {
        // and resume & close thread handles
        ResumeThread(g_hThreadHandles[i]);
        CloseHandle(g_hThreadHandles[i]);
    }

    // clean up
    free(g_hThreadHandles);
    g_hThreadHandles = NULL;
    g_nThreadHandles = 0;

	if (freeCtx != nullptr)
	{
		CloseProcessSnapshot(freeCtx);
	}
}

// get snapshot of the processes started in the system
static BOOL CreateProcessSnapshot(VOID** snapshotContext)
{
    ULONG   cbBuffer = 1024 * 1024;  // 1Mb - default process information buffer size (that's enough in most cases for high-loaded systems)
    LPVOID  pBuffer = NULL;
    NTSTATUS Status;

    do
    {
        pBuffer = malloc(cbBuffer);
        if (pBuffer == NULL)
        {
            return FALSE;
        }

        Status = fnZwQuerySystemInformation(Nt::SystemProcessInformation, pBuffer, cbBuffer, NULL);

        if (Status == STATUS_INFO_LENGTH_MISMATCH)
        {
            free(pBuffer);
            cbBuffer *= 2;
        }
        else
            if (!NT_SUCCESS(Status))
            {
                free(pBuffer);
                return FALSE;
            }
    } while (Status == STATUS_INFO_LENGTH_MISMATCH);

    *snapshotContext = pBuffer;

    return TRUE;
}

// find and return process information from snapshot
static Nt::PSYSTEM_PROCESS_INFORMATION FindProcess(VOID* snapshotContext, DWORD processId)
{
    Nt::PSYSTEM_PROCESS_INFORMATION currentProcess = (Nt::PSYSTEM_PROCESS_INFORMATION)snapshotContext;

    while (currentProcess != NULL)
    {
        if (static_cast<DWORD>(reinterpret_cast<DWORD_PTR>(currentProcess->uUniqueProcessId)) == processId)
        {
            break;
        }

        if (currentProcess->uNext == 0)
        {
            currentProcess = NULL;
        }
        else
        {
            currentProcess = (Nt::PSYSTEM_PROCESS_INFORMATION)(((LPBYTE)currentProcess) + currentProcess->uNext);
        }
    }

    return currentProcess;
}

//=========================================================================
// Internal function:
//
// Suspend all threads in this process while trying to make sure that their 
// instruction pointer is not in the given range.
//=========================================================================
BOOL SuspendOtherThreads(HOOK_CONTEXT* hookCtx, int hookCount, void **freeCtx)
{
    BOOL bRet = FALSE;

    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();

    VOID* procEnumerationCtx = NULL;
    Nt::PSYSTEM_PROCESS_INFORMATION procInfo = NULL;

    // get a view of the processes and threads in the system

    if (CreateProcessSnapshot(&procEnumerationCtx))
    {
        procInfo = FindProcess(procEnumerationCtx, pid);
        bRet = procInfo != NULL;
    }

    // count threads in this process (except for ourselves)
    DWORD nThreadsInProcess = 0;

    if (bRet)
    {
        if (procInfo->uThreadCount != 0)
        {
            nThreadsInProcess = procInfo->uThreadCount - 1;
        }

        ODPRINTF((L"mhooks: [%d:%d] SuspendOtherThreads: counted %d other threads", pid, tid, nThreadsInProcess));

        if (nThreadsInProcess)
        {
            // alloc buffer for the handles we really suspended
            g_hThreadHandles = (HANDLE*)malloc(nThreadsInProcess * sizeof(HANDLE));

            if (g_hThreadHandles)
            {
                ZeroMemory(g_hThreadHandles, nThreadsInProcess * sizeof(HANDLE));
                DWORD nCurrentThread = 0;
                BOOL bFailed = FALSE;

                // go through every thread

                for (ULONG threadIdx = 0; threadIdx < procInfo->uThreadCount; threadIdx++)
                {
                    DWORD threadId = static_cast<DWORD>(reinterpret_cast<DWORD_PTR>(procInfo->Threads[threadIdx].ClientId.UniqueThread));

                    if (threadId != tid)
                    {
                        // attempt to suspend it
                        g_hThreadHandles[nCurrentThread] = SuspendOneThreadEx(threadId, hookCtx, hookCount);

                        if (GOOD_HANDLE(g_hThreadHandles[nCurrentThread]))
                        {
                            ODPRINTF((L"mhooks: [%d:%d] SuspendOtherThreads: successfully suspended %d", pid, tid, threadId));
                            nCurrentThread++;
                        }
                        else
                        {
                            ODPRINTF((L"mhooks: [%d:%d] SuspendOtherThreads: error while suspending thread %d: %d", pid, tid, threadId, gle()));
                            // TODO: this might not be the wisest choice
                            // but we can choose to ignore failures on
                            // thread suspension. It's pretty unlikely that
                            // we'll fail - and even if we do, the chances
                            // of a thread's IP being in the wrong place
                            // is pretty small.
                            // bFailed = TRUE;
                        }
                    }
                }

                g_nThreadHandles = nCurrentThread;
                bRet = !bFailed;
            }
        }

        //TODO: we might want to have another pass to make sure all threads
        // in the current process (including those that might have been
        // created since we took the original snapshot) have been 
        // suspended.
    }
    else
    {
        ODPRINTF((L"mhooks: [%d:%d] SuspendOtherThreads: can't CreateProcessSnapshot: %d", pid, tid, gle()));
    }

    if (!bRet && nThreadsInProcess != 0)
    {
        ODPRINTF((L"mhooks: [%d:%d] SuspendOtherThreads: Had a problem (or not running multithreaded), resuming all threads.", pid, tid));
        ResumeOtherThreads(procEnumerationCtx);
		procEnumerationCtx = nullptr;
    }

	*freeCtx = procEnumerationCtx;

    return bRet;
}