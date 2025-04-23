#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>
typedef DWORD (WINAPI *TCsrGetProcessId)(VOID);

bool Check()
{
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll)
    {
        printf("Failed to load ntdll.dll\n");
        return false;
    }
    
    TCsrGetProcessId pfnCsrGetProcessId = (TCsrGetProcessId)GetProcAddress(hNtdll, "CsrGetProcessId");
    if (!pfnCsrGetProcessId)
    {
        printf("Failed to get address of CsrGetProcessId\n");
        return false;
    }

    DWORD processId = pfnCsrGetProcessId();
    HANDLE hCsr = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hCsr != NULL)
    {
        CloseHandle(hCsr);
        return true;
    }
    else
    {
        printf("Failed to open process with ID %lu\n", processId);
        return false;
    }
}

int main()
{
    if (Check())
    {
        printf("Process opened successfully!\n");
    }
    else
    {
        printf("Failed to open process.\n");
    }
    return 0;
}
