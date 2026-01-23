#include <windows.h>
#include <stdio.h>

int main()
{
	HANDLE hFile = CreateFileA("example.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}
	const char* text = "luongvd";
	DWORD bytesWritten;
	WriteFile(hFile, text, strlen(text), &bytesWritten, NULL);
	CloseHandle(hFile);
	return 0;
}
