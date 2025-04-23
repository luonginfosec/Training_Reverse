#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

bool Check()
{
    __try
    {
        CloseHandle((HANDLE)0xDEADBEEF);
        return false; 
    }
    __except (EXCEPTION_INVALID_HANDLE == GetExceptionCode()
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH)
    {
        return true;
    }
}

int main()
{
    if (Check())
        
    {
        printf("YES\n");
    }
    else
    {
        printf("NO\n");

    }

    return 0;
}
