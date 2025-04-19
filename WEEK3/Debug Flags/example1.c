#include <windows.h>
#include <stdio.h>  

int main(){

    printf("%s", "Kiem tra debug\n");

    if (IsDebuggerPresent()) {
        printf("%s", "Bat duoc ngay\n");
    } else {
        printf("%s", "Da thoat\n");
    }

    return 0;
}
