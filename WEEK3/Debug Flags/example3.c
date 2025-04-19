#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *TNtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

int main()
{
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) {
        fprintf(stderr, "Failed to load ntdll.dll\n");
        return 1;
    }

    TNtQueryInformationProcess pfnNtQueryInformationProcess = 
        (TNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (!pfnNtQueryInformationProcess) {
        fprintf(stderr, "Failed to get NtQueryInformationProcess\n");
        return 1;
    }

    ULONG_PTR debugPort = 0;
    ULONG returnedLength = 0;

    NTSTATUS status = pfnNtQueryInformationProcess(
        GetCurrentProcess(),
        (PROCESSINFOCLASS)7, 
        &debugPort,
        sizeof(debugPort),
        &returnedLength
    );

    if (NT_SUCCESS(status)) {
        printf("ProcessDebugPort: 0x%p\n", (PVOID)debugPort);

        if (debugPort == (ULONG_PTR)-1) {
            printf("Debugger detected via ProcessDebugPort!\n");
            ExitProcess(-1);
        }
    } else {
        fprintf(stderr, "NtQueryInformationProcess failed: 0x%08X\n", status);
    }
    return 0;
}
