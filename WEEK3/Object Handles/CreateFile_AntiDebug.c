#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>

bool Check()
{
    char szFileName[MAX_PATH];
    
    // Lấy đường dẫn đầy đủ của file thực thi hiện tại
    if (GetModuleFileNameA(NULL, szFileName, MAX_PATH) == 0)
    {
        printf("Failed to get module filename\n");
        return false;
    }
    
    // Thử mở file với quyền truy cập độc quyền
    HANDLE hFile = CreateFileA(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE)
    {
        // Không thể mở file với quyền truy cập độc quyền
        // Có thể file đang được mở bởi một trình gỡ lỗi
        printf("Failed to open file exclusively, debugger might be present\n");
        return true; // Trả về true nếu phát hiện debugger
    }
    
    // Đóng handle nếu mở thành công
    CloseHandle(hFile);
    return false; // Không phát hiện debugger
}

int main()
{
    if (Check())
    {
        printf("Debugger detected!\n");
    }
    else
    {
        printf("No debugger detected.\n");
    }
    return 0;
}