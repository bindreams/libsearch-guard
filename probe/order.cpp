// A C++ static constructor and a C constructor, as llvm-mingw's clang places them, each tagging the order and
// trying a flagless LoadLibrary of a DLL planted beside the exe.
#include <windows.h>
#include <string.h>
#include <stdio.h>

static void report(const char* slot, const wchar_t* dll) {
    char line[160];
    HMODULE m = LoadLibraryW(dll);
    DWORD err = m ? 0 : GetLastError();
    snprintf(line, sizeof line, "%s load=%s err=%lu\n", slot, m ? "ok" : "blocked", (unsigned long)err);
    DWORD w;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line, (DWORD)strlen(line), &w, 0);
}

struct Ctor {
    Ctor() { report("cxx-static-ctor", L"planted-cxx.dll"); }
};
static Ctor ctor_instance;

__attribute__((constructor)) static void c_constructor() { report("c-attribute-constructor", L"planted-cattr.dll"); }
