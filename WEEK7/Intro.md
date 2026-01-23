# TASK 07

- Tìm hiểu tất cả các kỹ thuật inject

- Nội dung nghiên cứu tìm hiểu lý thuyết này sử dụng tài liệu chính từ [MITRE](https://attack.mitre.org/techniques/T1055/001/)

- Nội dung trong đây gồm 12 công nghệ hay gặp.

Kẻ tấn công có thể tiêm mã vào tiến trình để né tránh các cơ chế phòng thủ cũng như có thể leo thang đặc quyền. **Process Injection** là một phương pháp cho phép thực hiện mã tùy ý trong không gian địa chỉ của một tiến trình đang chạy khác. Việc chạy mã trong ngữ cảnh của một tiến trình khác có thể cho ta truy cập vào bộ nhớ của tiến trình đó, tài nguyên hệ thống/mạng, và thậm chí có thể có đặc quyền cao hơn. Thực thi thông qua process injection cũng có thể giúp tránh bị rà soát bởi các công cụ do thực thi dưới tiến trình hợp pháp.

Có rất nhiều cách tiêm mã vào một tiến trình, nhiều kĩ thuật trong đó lợi dụng các chức năng hợp pháp. Những cách triển khai này tồn tại trên hầu hết các hệ điều hành lớn, nhưng thường mang tính đặc thù cho từng nền tảng.

Các con mã độc không chỉ tiêm code 1 lần vào 1 tiến trình, mà có thể nhiều lần vào nhiều tiến trình khác nhau.

Việc này giúp:
- Phân tách module -> thay vì để toàn bộ mã độc nằm trong một tiến trình thì dễ bị phát hiện, chúng chia nhỏ thành nhiều phần nằm rải rác trên nhiều tiến trình hợp pháp khác nhau.

Ví dụ:
- Giả sử có 1 con malware chia thành 3 module:
- Module A tiêm vào explorer.exe
- Module B tiêm vào chrome.exe
- Module C tiêm vào svhost.exe
Các module này nói chuyện qua named pines hoặc phối hợp.

Ví dụ:
Tiến trình A ghi dữ liệu vào ```\\.\pipe\myPipe``` tiến trình B đọc từ ```\\.\pipe\myPipe```

Sau khi đã tìm hiểu sơ sơ như vậy chúng ta tiếp tục đi sâu vào nghiên cứu từng phần.


## [[+] 1. DLL Injection](./Techniques/[+]%201.%20DLL%20injection.md/Process_Injection_Dynamic_link_Library_Injection.md)

## [[+] 2. Portable Executable Injection](./Techniques/[+]%201.%20DLL%20injection.md/Process_Injection_Dynamic_link_Library_Injection.md)

## [[+] 3. Thread Execution Hijacking](./Techniques/[+]%201.%20DLL%20injection.md/Process_Injection_Dynamic_link_Library_Injection.md)

## [[+] 4. Asynchronous Procedure Call](./Techniques/[+]%201.%20DLL%20injection.md/Process_Injection_Dynamic_link_Library_Injection.md)

## [[+] 5. Thread Local Storage](./Techniques/[+]%201.%20DLL%20injection.md/Process_Injection_Dynamic_link_Library_Injection.md)

## [[+] 6. Ptrace System Calls](./Techniques/[+]%201.%20DLL%20injection.md/Process_Injection_Dynamic_link_Library_Injection.md)

## [[+] 7. Proc Memory](./Techniques/[+]%201.%20DLL%20injection.md/Process_Injection_Dynamic_link_Library_Injection.md)

## [[+] 8. Extra Window Memory Injection](./Techniques/[+]%201.%20DLL%20injection.md/Process_Injection_Dynamic_link_Library_Injection.md)

## [[+] 9. Process Hollowing](./Techniques/[+]%201.%20DLL%20injection.md/Process_Injection_Dynamic_link_Library_Injection.md)

## [[+] 10. Process Doppelgänging](./Techniques/[+]%201.%20DLL%20injection.md/Process_Injection_Dynamic_link_Library_Injection.md)

## [[+] 11. VDSO Hijacking](./Techniques/[+]%201.%20DLL%20injection.md/Process_Injection_Dynamic_link_Library_Injection.md)

## [[+] 12. ListPlanting](./Techniques/[+]%201.%20DLL%20injection.md/Process_Injection_Dynamic_link_Library_Injection.md)

