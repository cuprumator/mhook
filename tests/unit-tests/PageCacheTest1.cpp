#include "stdafx.h"
#include "mhook-lib\mhook_internal.h"

typedef DWORD (WINAPI* PFN_GetEnvironmentVariableW)(LPCWSTR lpName, LPWSTR lpBuffer,DWORD nSize);

static const wchar_t g_MhookEnvVar[] = L"mhook_ut";
static const DWORD g_MhookEnvVarSize = _countof(g_MhookEnvVar);

static PFN_GetEnvironmentVariableW TrueGetEnvironmentVariableW = NULL;
static DWORD WINAPI Hook_GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer,DWORD nSize)
{
    if (0 == wcscmp(lpName, g_MhookEnvVar))
    {
        const DWORD outSize = min(nSize, g_MhookEnvVarSize);
        wcsncpy_s(lpBuffer, nSize, g_MhookEnvVar, outSize);
        return outSize;
    }
    return TrueGetEnvironmentVariableW(lpName, lpBuffer, nSize);
}

static std::wstring GetMHookUtVar()
{
    wchar_t out[g_MhookEnvVarSize + 1] = {0};
    DWORD outSize = GetEnvironmentVariableW(g_MhookEnvVar, out, _countof(out));

    if ((0 == outSize) && (ERROR_ENVVAR_NOT_FOUND == GetLastError()))
    {
        return std::wstring();
    }

    if (g_MhookEnvVarSize != outSize)
    {
        throw std::runtime_error("Invalid out size");
    }

    if (0 != wcscmp(out, g_MhookEnvVar))
    {
        throw std::runtime_error("Invalid out string");
    }

    return out;
}

static void CheckNoHook()
{
    ASSERT_EQ(std::wstring(), GetMHookUtVar());
}

static void CheckYesHook()
{
    ASSERT_EQ(std::wstring(g_MhookEnvVar), GetMHookUtVar());
}

TEST(PageCacheTest1, TestSimpleHook)
{
    //////////////////////////////////////////////////////////////////////////
    // Check init state
    MHOOKUT_GlobalVars gv;
    MHOOKUT_GetGlobalVars(&gv);
    RtlZeroMemory(gv.PagesCache, sizeof(PAGE_INFO*) * MHOOKS_MAX_SUPPORTED_HOOKS);
    ASSERT_EQ(0, gv.HooksInUse);

    CheckNoHook();
    //////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////
    // Set hook
    TrueGetEnvironmentVariableW = reinterpret_cast<PFN_GetEnvironmentVariableW>(GetProcAddress(GetModuleHandleW(L"kernel32"), "GetEnvironmentVariableW"));
    ASSERT_TRUE(FALSE != Mhook_SetHook(reinterpret_cast<PVOID*>(&TrueGetEnvironmentVariableW), Hook_GetEnvironmentVariableW));
    CheckYesHook();
    //////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////
    // Check page cache 
    MHOOKUT_GetGlobalVars(&gv);
    ASSERT_EQ(1, gv.HooksInUse);
    ASSERT_TRUE(NULL != gv.PagesCache[0]);
    ASSERT_EQ(1, gv.PagesCache[0]->counter);

    for (int i = 1; i < MHOOKS_MAX_SUPPORTED_HOOKS; ++i)
    {
        ASSERT_TRUE(NULL == gv.PagesCache[i]);
    }
    //////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////
    // Unhook
    ASSERT_TRUE(FALSE != Mhook_Unhook(reinterpret_cast<PVOID*>(&TrueGetEnvironmentVariableW)));
    CheckNoHook();
    //////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////
    // Check page cache 
    MHOOKUT_GetGlobalVars(&gv);
    ASSERT_EQ(0, gv.HooksInUse);
    ASSERT_TRUE(NULL != gv.PagesCache[0]);
    ASSERT_EQ(1, gv.PagesCache[0]->counter);

    for (int i = 1; i < MHOOKS_MAX_SUPPORTED_HOOKS; ++i)
    {
        ASSERT_TRUE(NULL == gv.PagesCache[i]);
    }
    //////////////////////////////////////////////////////////////////////////
}

TEST(PageCacheTest1, TestPageCacheFilled)
{
    //////////////////////////////////////////////////////////////////////////
    // Fake fill of page cache
    MHOOKUT_GlobalVars gv;
    MHOOKUT_GetGlobalVars(&gv);
    ASSERT_EQ(0, gv.HooksInUse);

    PAGE_INFO* fakePage = reinterpret_cast<PAGE_INFO*>(VirtualAlloc(NULL, gv.PageSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    ASSERT_TRUE(NULL != fakePage);

    fakePage->counter = gv.TramplinesInPage;

    for (DWORD i = 0; i < gv.TramplinesInPage; ++i)
    {
        memset(&fakePage->pTramplines[i], 1, sizeof(MHOOKS_TRAMPOLINE));
    }
    for (int i = 0; i < MHOOKS_MAX_SUPPORTED_HOOKS; ++i)
    {
        gv.PagesCache[i] = fakePage;
    }

    CheckNoHook();
    //////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////
    // Try set any hook
    TrueGetEnvironmentVariableW = reinterpret_cast<PFN_GetEnvironmentVariableW>(GetProcAddress(GetModuleHandleW(L"kernel32"), "GetEnvironmentVariableW"));
    ASSERT_TRUE(FALSE != Mhook_SetHook(reinterpret_cast<PVOID*>(&TrueGetEnvironmentVariableW), Hook_GetEnvironmentVariableW));
    CheckYesHook();
    //////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////
    // Check page cache 
    MHOOKUT_GetGlobalVars(&gv);
    ASSERT_EQ(1, gv.HooksInUse);

    ASSERT_TRUE(NULL != gv.Hooks[0]);
    ASSERT_EQ(1, gv.Hooks[0]->pPageInfo->counter);

    for (int i = 0; i < MHOOKS_MAX_SUPPORTED_HOOKS; ++i)
    {
        ASSERT_TRUE(fakePage == gv.PagesCache[i]) << i;
        ASSERT_TRUE(gv.Hooks[0]->pPageInfo != gv.PagesCache[i]) << i;
    }

    for (int i = 1; i < MHOOKS_MAX_SUPPORTED_HOOKS; ++i)
    {
        ASSERT_TRUE(NULL == gv.Hooks[i]) << i;
    }
    //////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////
    // Unhook
    ASSERT_TRUE(FALSE != Mhook_Unhook(reinterpret_cast<PVOID*>(&TrueGetEnvironmentVariableW)));
    CheckNoHook();
    //////////////////////////////////////////////////////////////////////////
    ::VirtualFree(fakePage, 0, MEM_RELEASE);
}