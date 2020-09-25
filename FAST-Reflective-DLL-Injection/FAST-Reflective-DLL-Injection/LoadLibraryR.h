#pragma once
#include <Windows.h>

DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer, const char* exportedFuncName);

HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter, const char *exportedFuncName);

