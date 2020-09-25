#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "LoadLibraryR.h"

int main(int argc, char *argv[])
{
	HANDLE hFile = NULL;
	HANDLE hModule = NULL;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	DWORD dwProcessId = 0;
	DWORD dwLength = 0;
	LPVOID lpBuffer = NULL;
	TOKEN_PRIVILEGES priv = { 0 };

	FILE* fp = NULL;

	if (argc != 4) {
		printf("usage: %s <dll> <exported_function_name> <pid>\n", argv[0]);
		printf("<exported_function_name>: Exported function name in DLL (function using __declspec(dllexport))\n");
		return 0;
	}

	const char* cpDllFile = argv[1], *exportedFuncName = argv[2];

	dwProcessId = atoi(argv[3]);

	fopen_s(&fp, cpDllFile, "rb");
	if (fp == NULL) {
		printf("Error: file not found.\n");
		return 1;
	}

	fseek(fp, 0L, SEEK_END);
	dwLength = ftell(fp);
	fseek(fp, 0L, SEEK_SET);

	lpBuffer = malloc(dwLength);
	if (lpBuffer == NULL) {
		printf("Error: cannot allocate heap.\n");
		return 1;
	}

	fread(lpBuffer, 1, dwLength, fp);
	fclose(fp);

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
		{
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
		}

		CloseHandle(hToken);
	}

	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
	if (hProcess == NULL) {
		printf("Error: cannot open the target process.\n");
		return 1;
	}

	hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL, exportedFuncName);
	if (hModule == NULL) {
		printf("Error: cannot inject %s DLL file.\n", cpDllFile);
		return 1;
	}

	printf("Injected the %s DLL into process %d.\n", cpDllFile, dwProcessId);
	WaitForSingleObject(hModule, -1);

	if (lpBuffer)
		free(lpBuffer);
	
	if (hProcess)
		CloseHandle(hProcess);

	return 0;
}