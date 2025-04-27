# Anti-Debug: Process Memory

## Process Memory

Bộ nhớ tiến trình: một tiến trình có thể kiểm tra bộ nhớ của chính nó để phát hiện sự hiện diện của trình gỡ lỗi hoặc can thiệp vào trình gỡ lỗi.

Phần này bao gồm việc kiểm tra bộ nhớ tiến trình và kiểm tra bối cảnh của các luồng, tìm kiếm các điểm dừng (breakpoint) và vá các hàm như là các phương pháp chống gắn kết (anti-attaching).

## 1. Breakpoints

Luôn có thể kiểm tra bộ nhớ tiến trình và tìm kiếm các điểm dừng phần mềm trong mã, hoặc kiểm tra các thanh ghi gỡ lỗi của CPU để xác định các điểm dừng phần cứng có được thiết lập hay không.


### 1.1. Software Breakpoints (INT3)

Ý tưởng là xác định mã máy của một số hàm để tìm byte 0xCC, đại diện cho lệnh INT 3 trong hợp ngữ (assembly).

Phương pháp này có thể tạo ra nhiều trường hợp sai, vì vậy cần phải sử dụng cẩn thận.

```C
#include <stdio.h>
#include <windows.h>
#include <stdbool.h>

void Function1() {
    printf("Function1 is running...\n");
}

void Function2() {
    printf("Function2 is running...\n");
}

void Function3() {
    printf("Function3 is running...\n");
}

bool CheckForSpecificByte(BYTE cByte, void* pMemory, SIZE_T nMemorySize) {
    BYTE* pBytes = (BYTE*)pMemory;

    for (SIZE_T i = 0; ; i++) {
        if ((nMemorySize > 0 && i >= nMemorySize) ||
            (nMemorySize == 0 && pBytes[i] == 0xC3)) {
            break;
        }

        if (pBytes[i] == cByte) {
            return true;
        }
    }
    return false;
}

bool IsDebugged() {
    void* functionsToCheck[] = {
        (void*)&Function1,
        (void*)&Function2,
        (void*)&Function3,
    };

    for (int i = 0; i < sizeof(functionsToCheck) / sizeof(void*); i++) {
        if (CheckForSpecificByte(0xCC, functionsToCheck[i], 0)) {
            return true;
        }
    }

    return false;
}

int main() {
    if (IsDebugged()) {
        printf("Debugger detected! Exiting...\n");
        return 1;
    }
    else {
        printf("No debugger detected.\n");
    }
    Function1();
    Function2();
    Function3();
    return 0;
}

```

### 1.2. Anti-Step-Over

Trình gỡ lỗi cho phép bạn thực hiện thao tác "step over" (bước qua) lệnh gọi hàm (F8).Trong trường hợp này, trình gỡ lỗi ngầm đặt một breakpoint phần mềm tại lệnh ngay sau lời gọi hàm (tức là tại địa chỉ trả về của hàm được gọi).

Để phát hiện việc có ai đó đang cố step over hàm, ta có thể kiểm tra byte đầu tiên tại địa chỉ trả về. Nếu tại địa chỉ trả về có chứa breakpoint phần mềm (0xCC), ta có thể ghi đè nó bằng một lệnh khác (ví dụ như NOP). Điều này nhiều khả năng sẽ làm hỏng luồng thực thi và khiến chương trình bị crash.

Mặt khác, ta cũng có thể ghi đè địa chỉ trả về bằng một đoạn mã có ý nghĩa thay vì NOP, từ đó thay đổi luồng điều khiển của chương trình.

#### 1.2.1 Direct Memory Modification (Sửa đổi bộ nhớ trực tiếp)

Từ bên trong hàm, chúng ta có thể kiểm tra breakpoint phần mềm (software breakpoint) nào được đặt ngay sau lệnh gọi hàm hay không. Cách làm là đọc 1 byte tại địa chỉ trả về (return address), và nếu byte đó bằng 0xCC (lệnh INT 3), thì có thể ghi đè nó bằng 0x90 lệnh NOP.

Việc này có thể khiến chương trình bị crash, vì ta đã làm hỏng lệnh tại địa chỉ trả về. Tuy nhiên, nếu bạn biết chính xác lệnh nào sẽ được thực thi khi hàm kết thúc, thì bạn có thể thay thế breakpoint bằng byte đầu tiên của lệnh đó.

```C
#include <intrin.h>
void foo(){
    PVOID pRetAddr = _ReturnAddress();
    if(*(PBYTE)pRetAddress == 0xCC) // int 3
    {
        DWORD dwOldProtect;
        if (VirtualProtect(pRetAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        {
            *(PBYTE)pRetAddress = 0x90; // nop
            VirtualProtect(pRetAddress, 1, dwOldProtect, &dwOldProtect);
        }
    }
}
```

#### 1.2.2. ReadFile()

Phương thức này sử dụng hàm ReadFile() của kernel32.dll để patch lại đoạn mã tại địa chỉ trả về (return address).

Ý tưởng là đọc chính file thực thi (executable file) của tiến trình hiện tại và truyền địa chỉ trả về làm bộ đệm xuất (output buffer) cho kernel32!ReadFile(). Byte tại địa chỉ trả về sẽ bị ghi đè bằng ký tự ‘M’, và tiến trình có khả năng sẽ bị crash (sập).


```C
void foo()
{
    PVOID pRetAddress = _ReturnAddress();
    if (*(PBYTE)pRetAddress == 0xCC)
    {
        DWORD dwOldProtect, dwRead;
        CHAR szFilePath[MAX_PATH];
        HANDLE hFile;

        if (VirtualProtect(pRetAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        {
            if (GetModuleFileNameA(NULL, szFilePath, MAX_PATH))
            {
                hFile = CreateFileA(szFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                if (hFile != INVALID_HANDLE_VALUE)
                {
                    ReadFile(hFile, pRetAddress, 1, &dwRead, NULL);
                    CloseHandle(hFile);
                }
            }
            VirtualProtect(pRetAddress, 1, dwOldProtect, &dwOldProtect);
        }
    }
}
```


#### 1.2.3. WriteProcessMemory()

Phương pháp này sử dụng hàm kernel32!WriteProcessMemory() để chỉnh sửa mã tại địa chỉ trả về.

[WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)

```
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,                     // GetCurrentProcess()
  [in]  LPVOID  lpBaseAddress,                // pRetAddress
  [in]  LPCVOID lpBuffer,                     // NOP byte
  [in]  SIZE_T  nSize,                        // 1
  [out] SIZE_T  *lpNumberOfBytesWritten       // NULL
);
```

#### 1.2.4. Toolhelp32ReadProcessMemory()

Hàm ```kernel32!Toolhelp32ReadProcessMemory()``` cho phép bạn đọc bộ nhớ của các tiến trình khác. Tuy nhiên nó cũng có thể được dùng để chống step-over.

```C
#include <TLHelp32.h>

bool foo(){
    PVOID pRetAddr = _ReturnAddress();
    BYTE uByte;
    if (FALSE != Toolhelp32ReadProcessMemory(GetCurrentProcessId(), _ReturnAddress(), &uByte, sizeof(BYTE), NULL)){
        if (uByte == 0xCC)
            ExitProcess(0);
    }
}
```


### 1.3. Memory Breakpoints

Sử dụng guard page trong bộ nhớ (page này được bảo vệ bởi OS). Nếu page này bị truy cập lần đầu, nó sẽ raise STATUSGUARDVIOLATION exception.

Guard page được tạo bằng cách sử dụng PAGE_GUARD memory protection option khi sử dụng API VirtualProtect.

```C
DWORD dwOldProtect = 0;
SYSTEM_INFO sysinfo = {0};

GetSystemInfo(&SysInfo);
PVOID pPage = VirtualAlloc(NULL, sysinfo.dwPageSize, MEM_COMMIT|MEM_REVERSE, PAGE_EXECUTE_READWRIRE);

// in new allocated mem
PBYTE pMem = (PBYTE)pPage;
*pMem = 0xC3; // ret instruction
// make the page a guard page
VirtualProtect(pPage, sysinfo.dwPageSize, PAGE_EXECUTE_READWRIRE| PAGE_GUARD, &dwOldProtect); // flNewProtect = 140h

__try{
    __asm{
        mov eax, pPage
        push mem_bp_being_debugged
        jmp eax
        // after jmp into new allocated mem, it will ret mem_bp_being_debugged
    }
}__except(EXCEPTION_EXECUTE_HANDLER){
    VirtualFree(pPage, NULL, MEM_RELEASE);
    return false;
}
mem_bp_being_debugged:
    VirtualFree(pPage, NULL, MEM_RELEASE);
    return true;

```


### 1.4 Hardware Breakpoints


Các thanh ghi debug DR0, DR1, DR2 và DR3 có thể được truy xuất từ context của luồng (thread context). Nếu bất kỳ thanh ghi nào trong số này chứa giá trị khác 0, điều đó có thể cho thấy chương trình đang chạy dưới một trình gỡ lỗi và có một hardware breakpoint đã được thiết lập.

```C
#include <windows.h>
#include <stdbool.h>
bool IsDebugged()
{
    CONTEXT ctx;  
    ZeroMemory(&ctx, sizeof(CONTEXT)); 
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;  
    if (!GetThreadContext(GetCurrentThread(), &ctx))
        return false;  
    return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}
```

