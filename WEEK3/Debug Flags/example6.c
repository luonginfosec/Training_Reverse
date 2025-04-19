#include <windows.h>
#include <stdio.h>
#include <stdbool.h> // Required for bool, true, false

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemKernelDebuggerInformation = 0x23
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

bool CheckKernelDebugger()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return false;

    SYSTEM_KERNEL_DEBUGGER_INFORMATION debuggerInfo;
    NTSTATUS status = NtQuerySystemInformation(
        SystemKernelDebuggerInformation,
        &debuggerInfo,
        sizeof(debuggerInfo),
        NULL
    );

    return NT_SUCCESS(status) &&
           debuggerInfo.DebuggerEnabled &&
           !debuggerInfo.DebuggerNotPresent;
}

int main()
{
    if (CheckKernelDebugger()) {
        printf("Kernel debugger is enabled and present!\n");
    } else {
        printf("No kernel debugger detected.\n");
    }

    return 0;
}
