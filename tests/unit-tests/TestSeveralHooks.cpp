#include "stdafx.h"
#include "mhook-lib\mhook_internal.h"


int __declspec(noinline) __cdecl FuncForSeveralHook1()
{
    return 1;
}

typedef decltype(&FuncForSeveralHook1) FuncType1;

FuncType1 TrueFunc1;
int __declspec(noinline) __cdecl Hook_FuncForSeveralHook1()
{
    int res = TrueFunc1();
    return (-1)*res;
}

int __declspec(noinline) __cdecl FuncForSeveralHook2()
{
    return 2;
}

typedef decltype(&FuncForSeveralHook2) FuncType2;

FuncType2 TrueFunc2;
int __declspec(noinline) __cdecl Hook_FuncForSeveralHook2()
{
    int res = TrueFunc2();
    return (-1)*res;
}

TEST(TestSeveralHooks, Basic)
{
    TrueFunc1 = FuncForSeveralHook1;
    TrueFunc2 = FuncForSeveralHook2;
    HOOK_INFO hooks[2] = {
        {
            (void**)&TrueFunc1,
            Hook_FuncForSeveralHook1,
            MHOOK_HOOK_FAILED,
            nullptr
        },
        {
            (void**)&TrueFunc2,
            Hook_FuncForSeveralHook2,
            MHOOK_HOOK_FAILED,
            nullptr
        }
    };

    ::Mhook_SetHookEx(hooks, ARRAYSIZE(hooks));
    ASSERT_EQ(-1, FuncForSeveralHook1());
    ASSERT_EQ(-2, FuncForSeveralHook2());
}