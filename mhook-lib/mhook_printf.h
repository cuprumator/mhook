#pragma once

//=========================================================================
#ifndef ODPRINTF

#ifdef _DEBUG
#define ODPRINTF(a) odprintf a
#else
#define ODPRINTF(a)
#endif

inline void __cdecl odprintf(PCSTR format, ...) {
    va_list	args;
    va_start(args, format);
    int len = _vscprintf(format, args);
    if (len > 0) {
        len += (1 + 2);
        PSTR buf = (PSTR)malloc(len);
        if (buf) {
            len = vsprintf_s(buf, len, format, args);
            if (len > 0) {
                while (len && isspace(buf[len - 1])) len--;
                buf[len++] = '\r';
                buf[len++] = '\n';
                buf[len] = 0;
                OutputDebugStringA(buf);
            }
            free(buf);
        }
        va_end(args);
    }
}

inline void __cdecl odprintf(PCWSTR format, ...) {
    va_list	args;
    va_start(args, format);
    int len = _vscwprintf(format, args);
    if (len > 0) {
        len += (1 + 2);
        PWSTR buf = (PWSTR)malloc(sizeof(WCHAR)*len);
        if (buf) {
            len = vswprintf_s(buf, len, format, args);
            if (len > 0) {
                while (len && iswspace(buf[len - 1])) len--;
                buf[len++] = L'\r';
                buf[len++] = L'\n';
                buf[len] = 0;
                OutputDebugStringW(buf);
            }
            free(buf);
        }
        va_end(args);
    }
}

#endif //#ifndef ODPRINTF