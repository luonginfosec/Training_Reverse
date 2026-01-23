	#include<stdio.h>
	#include<windows.h>

	const char* k = "[+]";
	const char* e = "[-]";
	const char* i = "[*]";

	DWORD PID, TID = NULL;
	LPVOID rBuffer = NULL;	
	HMODULE hKernel32 = NULL;
	HANDLE hProcess = NULL, hThread = NULL;

	wchar_t dllPath[MAX_PATH] = L"D:\\LuongVD.dll";
	size_t dllPathSize = sizeof(dllPath);


	int main(int argc, char* argv[]) {
		if (argc < 2) {
			printf("%s Usage: %s", e, argv[0]);
			return EXIT_FAILURE;
		}
		PID = atoi(argv[1]);
		printf("%s Trying to get a handle to the process (%ld)\n", i, PID);
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
		if (hProcess == NULL) {
			printf("%s Failed to get a handle to the process, error: %ld\n", e, GetLastError());
			return EXIT_FAILURE;
		}
		printf("%s Got a handle to the process (%p)\n", k, hProcess);
		rBuffer = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (rBuffer == NULL) {
			printf("%s couldn't create rBuffer, error: %ld\n", e, GetLastError());
			return EXIT_FAILURE;
		}
		printf("%s allocated buffer to process memory w/ PAGE_READWRITE permission\n", k);

		WriteProcessMemory(hProcess, rBuffer, (LPVOID)dllPath, dllPathSize, NULL);
		printf("%s wrote [%S] to process memory\n", k, dllPath);

		hKernel32 = GetModuleHandleW(L"Kernel32");
		if (hKernel32 == NULL) {
			printf("%s couldn't get handle to Kernel32, error: %ld\n", e, GetLastError());
			CloseHandle(hProcess);
			return EXIT_FAILURE;
		}
		printf("%s got handle to Kernel32 (%p)\n", k, hKernel32);
		LPTHREAD_START_ROUTINE startThis = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
		if (startThis == NULL) {
			printf("%s couldn't get address of LoadLibraryW, error: %ld\n", e, GetLastError());
			VirtualFreeEx(hProcess, rBuffer, 0, MEM_RELEASE);
			CloseHandle(hProcess);
			return EXIT_FAILURE;
		}
		printf("%s got address of LoadLibraryW (%p)\n", k, startThis);
		hThread = CreateRemoteThread(hProcess, NULL, 0, startThis, rBuffer, 0, &TID);
		if (hThread == NULL) {
			printf("%s couldn't create remote thread, error: %ld\n", e, GetLastError());
			VirtualFreeEx(hProcess, rBuffer, 0, MEM_RELEASE);
			CloseHandle(hProcess);
			return EXIT_FAILURE;
		}
		printf("%s got a handle to the newly-created thread (%ld)\n\\--0x%p\n", k, TID, hThread);
		printf("%s waiting for the thread to finish execution\n", i);
		WaitForSingleObject(hThread, INFINITE);
		printf("%s thread finished execution\n", k);
		CloseHandle(hThread);
		CloseHandle(hProcess);
		return EXIT_SUCCESS;
	}