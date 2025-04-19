#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *TNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

int main()
{
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll)
    {
        TNtQueryInformationProcess pfnNtQueryInformationProcess = 
            (TNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

        if (pfnNtQueryInformationProcess)
        {
            DWORD dwReturned = 0;
            HANDLE hProcessDebugObject = NULL;
            const DWORD ProcessDebugObjectHandle = 0x1E;

            NTSTATUS status = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugObjectHandle,
                &hProcessDebugObject,
                sizeof(HANDLE),
                &dwReturned);

            if (status == 0 && hProcessDebugObject != NULL)
            {
                MessageBoxA(NULL, "Bi be r", "Status", MB_OK);
                ExitProcess(-1);
            }
        }
    }

    MessageBoxA(NULL, "Khong bi be", "Status", MB_OK);
    return 0;
}
