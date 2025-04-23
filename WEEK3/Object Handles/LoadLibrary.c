#include <windows.h>
#include <stdio.h>

BOOL Check()
{
    CHAR szBuffer[] = "C:\\Windows\\System32\\calc.exe";
    
    LoadLibraryA(szBuffer);

    // Try opening the file
    HANDLE hFile = CreateFileA(
        szBuffer,          // File name
        GENERIC_READ,      // Desired access
        0,                 // Share mode
        NULL,              // Security attributes
        OPEN_EXISTING,     // Creation disposition
        0,                 // Flags and attributes
        NULL               // Template file
    );

    return (hFile == INVALID_HANDLE_VALUE);
}

int main()
{
    if (Check()) {
        printf("File could not be opened.\n");
    } else {
        printf("File opened successfully.\n");
    }
    return 0;
}
