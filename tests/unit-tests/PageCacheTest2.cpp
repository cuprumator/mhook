#include "stdafx.h"
#include "mhook-lib\mhook_internal.h"

typedef int(__cdecl *PFN_FuncForHook)();
typedef bool(__cdecl *PFN_SetHook)();

struct FuncInfo
{
    PFN_FuncForHook Func;
    PFN_SetHook SetHook;
    int FuncHookedRes;
    int FuncRes;
};

#define DECLARE_FUNC_HOOK(N)                        \
PFN_FuncForHook TrueFuncForHook##N = NULL;          \
int __declspec(noinline) __cdecl FuncForHook##N()                        \
{                                                   \
    return N;                                       \
}                                                   \
int __declspec(noinline) __cdecl Hook_FuncForHook##N()                   \
{                                                   \
    int res = TrueFuncForHook##N();                 \
    return (-1)*res;                                \
}                                                   \
bool __declspec(noinline) __cdecl SetHook_FuncForHook##N()               \
{                                                   \
    TrueFuncForHook##N = FuncForHook##N;            \
    return (FALSE != Mhook_SetHook(reinterpret_cast<PVOID*>(&TrueFuncForHook##N), Hook_FuncForHook##N)); \
}

DECLARE_FUNC_HOOK(1);
DECLARE_FUNC_HOOK(2);
DECLARE_FUNC_HOOK(3);
DECLARE_FUNC_HOOK(4);
DECLARE_FUNC_HOOK(5);
DECLARE_FUNC_HOOK(6);
DECLARE_FUNC_HOOK(7);
DECLARE_FUNC_HOOK(8);
DECLARE_FUNC_HOOK(9);
DECLARE_FUNC_HOOK(10);
DECLARE_FUNC_HOOK(11);
DECLARE_FUNC_HOOK(12);
DECLARE_FUNC_HOOK(13);
DECLARE_FUNC_HOOK(14);
DECLARE_FUNC_HOOK(15);
DECLARE_FUNC_HOOK(16);
DECLARE_FUNC_HOOK(17);
DECLARE_FUNC_HOOK(18);
DECLARE_FUNC_HOOK(19);
DECLARE_FUNC_HOOK(20);
DECLARE_FUNC_HOOK(21);
DECLARE_FUNC_HOOK(22);
DECLARE_FUNC_HOOK(23);
DECLARE_FUNC_HOOK(24);
DECLARE_FUNC_HOOK(25);
DECLARE_FUNC_HOOK(26);
DECLARE_FUNC_HOOK(27);
DECLARE_FUNC_HOOK(28);
DECLARE_FUNC_HOOK(29);
DECLARE_FUNC_HOOK(30);
DECLARE_FUNC_HOOK(31);
DECLARE_FUNC_HOOK(32);
DECLARE_FUNC_HOOK(33);
DECLARE_FUNC_HOOK(34);
DECLARE_FUNC_HOOK(35);
DECLARE_FUNC_HOOK(36);
DECLARE_FUNC_HOOK(37);
DECLARE_FUNC_HOOK(38);
DECLARE_FUNC_HOOK(39);
DECLARE_FUNC_HOOK(40);
DECLARE_FUNC_HOOK(41);
DECLARE_FUNC_HOOK(42);
DECLARE_FUNC_HOOK(43);
DECLARE_FUNC_HOOK(44);
DECLARE_FUNC_HOOK(45);
DECLARE_FUNC_HOOK(46);
DECLARE_FUNC_HOOK(47);
DECLARE_FUNC_HOOK(48);
DECLARE_FUNC_HOOK(49);
DECLARE_FUNC_HOOK(50);
DECLARE_FUNC_HOOK(51);
DECLARE_FUNC_HOOK(52);
DECLARE_FUNC_HOOK(53);
DECLARE_FUNC_HOOK(54);
DECLARE_FUNC_HOOK(55);
DECLARE_FUNC_HOOK(56);
DECLARE_FUNC_HOOK(57);
DECLARE_FUNC_HOOK(58);
DECLARE_FUNC_HOOK(59);
DECLARE_FUNC_HOOK(60);
DECLARE_FUNC_HOOK(61);
DECLARE_FUNC_HOOK(62);
DECLARE_FUNC_HOOK(63);
DECLARE_FUNC_HOOK(64);
DECLARE_FUNC_HOOK(65);

#define LoadSetHook(N)                              \
{                                                   \
    fi[N - 1].SetHook = SetHook_FuncForHook##N;     \
    fi[N - 1].Func = FuncForHook##N;                \
    fi[N - 1].FuncRes = N;                          \
    fi[N - 1].FuncHookedRes = (N) * (-1);           \
}

void LoadSetHookArray(FuncInfo fi[MHOOKS_MAX_SUPPORTED_HOOKS + 1])
{
    LoadSetHook(1);
    LoadSetHook(2);
    LoadSetHook(3);
    LoadSetHook(4);
    LoadSetHook(5);
    LoadSetHook(6);
    LoadSetHook(7);
    LoadSetHook(8);
    LoadSetHook(9);
    LoadSetHook(10);
    LoadSetHook(11);
    LoadSetHook(12);
    LoadSetHook(13);
    LoadSetHook(14);
    LoadSetHook(15);
    LoadSetHook(16);
    LoadSetHook(17);
    LoadSetHook(18);
    LoadSetHook(19);
    LoadSetHook(20);
    LoadSetHook(21);
    LoadSetHook(22);
    LoadSetHook(23);
    LoadSetHook(24);
    LoadSetHook(25);
    LoadSetHook(26);
    LoadSetHook(27);
    LoadSetHook(28);
    LoadSetHook(29);
    LoadSetHook(30);
    LoadSetHook(31);
    LoadSetHook(32);
    LoadSetHook(33);
    LoadSetHook(34);
    LoadSetHook(35);
    LoadSetHook(36);
    LoadSetHook(37);
    LoadSetHook(38);
    LoadSetHook(39);
    LoadSetHook(40);
    LoadSetHook(41);
    LoadSetHook(42);
    LoadSetHook(43);
    LoadSetHook(44);
    LoadSetHook(45);
    LoadSetHook(46);
    LoadSetHook(47);
    LoadSetHook(48);
    LoadSetHook(49);
    LoadSetHook(50);
    LoadSetHook(51);
    LoadSetHook(52);
    LoadSetHook(53);
    LoadSetHook(54);
    LoadSetHook(55);
    LoadSetHook(56);
    LoadSetHook(57);
    LoadSetHook(58);
    LoadSetHook(59);
    LoadSetHook(60);
    LoadSetHook(61);
    LoadSetHook(62);
    LoadSetHook(63);
    LoadSetHook(64);
    LoadSetHook(65);

    ASSERT_EQ(MHOOKS_MAX_SUPPORTED_HOOKS + 1, 65);
}

TEST(PageCacheTest2, TestHooksInOnePage)
{
    //////////////////////////////////////////////////////////////////////////
    // Check init state
    MHOOKUT_GlobalVars gv;
    MHOOKUT_GetGlobalVars(&gv);
    RtlZeroMemory(gv.PagesCache, sizeof(PAGE_INFO*) * MHOOKS_MAX_SUPPORTED_HOOKS);
    ASSERT_EQ(0, gv.HooksInUse);

    FuncInfo fi[MHOOKS_MAX_SUPPORTED_HOOKS + 1];
    LoadSetHookArray(fi);

    for (int i = 0; i < _countof(fi); ++i)
    {
        ASSERT_EQ(fi[i].FuncRes, fi[i].Func());
    }
    //////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////
    // Set hooks (number == hooks in page)
    auto func = FuncForHook1;
    ASSERT_EQ(1, func());
    ASSERT_TRUE(SetHook_FuncForHook1());
    ASSERT_EQ(-1, func());
    MHOOKUT_GetGlobalVars(&gv);
    const DWORD hooksInPage = gv.TramplinesInPage;

    for (DWORD i = 1; i < hooksInPage; ++i)
    {
        ASSERT_TRUE(fi[i].SetHook()) << i;
    }
    //////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////
    // Check all funcs for hook
    for (DWORD i = 0; i < hooksInPage; ++i)
    {
        ASSERT_EQ(fi[i].FuncHookedRes, fi[i].Func());
    }
    for (DWORD i = hooksInPage; i < _countof(fi); ++i)
    {
        ASSERT_EQ(fi[i].FuncRes, fi[i].Func());
    }
    //////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////
    // Check page cache (all setted hooks in first page)
    MHOOKUT_GetGlobalVars(&gv);

    ASSERT_EQ(hooksInPage, gv.HooksInUse);
    ASSERT_EQ(hooksInPage, gv.TramplinesInPage);
    ASSERT_TRUE(NULL != gv.PagesCache[0]);
    ASSERT_EQ(hooksInPage, gv.PagesCache[0]->counter);

    for (int i = 1; i < MHOOKS_MAX_SUPPORTED_HOOKS; ++i)
    {
        ASSERT_TRUE(NULL == gv.PagesCache[i]);
    }
    //////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////
    // Set next hook (must allocate new page) 
    ASSERT_EQ(fi[hooksInPage].FuncRes, fi[hooksInPage].Func());
    ASSERT_TRUE(fi[hooksInPage].SetHook());
    ASSERT_EQ(fi[hooksInPage].FuncHookedRes, fi[hooksInPage].Func());
    //////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////
    // Check all funcs for hook
    for (DWORD i = 0; i < (hooksInPage + 1); ++i)
    {
        ASSERT_EQ(fi[i].FuncHookedRes, fi[i].Func());
    }
    for (DWORD i = (hooksInPage + 1); i < _countof(fi); ++i)
    {
        ASSERT_EQ(fi[i].FuncRes, fi[i].Func());
    }
    //////////////////////////////////////////////////////////////////////////

    //////////////////////////////////////////////////////////////////////////
    // Check page cache (allocated 2 pages)
    MHOOKUT_GetGlobalVars(&gv);

    ASSERT_EQ(hooksInPage + 1, gv.HooksInUse);
    ASSERT_EQ(hooksInPage, gv.TramplinesInPage);

    ASSERT_TRUE(NULL != gv.PagesCache[0]);
    ASSERT_EQ(hooksInPage, gv.PagesCache[0]->counter);

    ASSERT_TRUE(NULL != gv.PagesCache[1]);
    ASSERT_EQ(1, gv.PagesCache[1]->counter);

    for (int i = 2; i < MHOOKS_MAX_SUPPORTED_HOOKS; ++i)
    {
        ASSERT_TRUE(NULL == gv.PagesCache[i]);
    }
    //////////////////////////////////////////////////////////////////////////
}