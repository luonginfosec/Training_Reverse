#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *TNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength OPTIONAL
);

int main() {
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) {
        printf("Khong the tai ntdll.dll\n");
        return 1;
    }

    TNtQueryInformationProcess NtQueryInformationProcess =
        (TNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        printf("Khong the lay dia chi NtQueryInformationProcess\n");
        return 1;
    }

    ULONG debugFlags = 0;

    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),        
        (PROCESSINFOCLASS)0x1F,    
        &debugFlags,                
        sizeof(debugFlags),         
        NULL                        
    );

    if (status == 0 ) {
        if (debugFlags == 0) {
            printf("[!] Da phat hien debugger (debugFlags = 0)\n");
        } else {
            printf("[+] Khong phat hien debugger (debugFlags = %lu)\n", debugFlags);
        }
    } else {
        printf("Loi khi goi NtQueryInformationProcess: 0x%X\n", status);
    }

    return 0;
}
