#include <windows.h>
#include <stdio.h>

int main() {
    BOOL isRemoteDebuggerPresent = FALSE;
    HANDLE hProcess = GetCurrentProcess();

    if (CheckRemoteDebuggerPresent(hProcess, &isRemoteDebuggerPresent) && isRemoteDebuggerPresent == TRUE) {
        printf("[!] Bắt được ngay.\n");
    } else {
        printf("[+] Không bị bắt rồi.\n");
    }

    return 0;
}
