.386 ; Chỉ định sử dụng bộ xử lí Intel 80386 trở lên
.model flat, stdcall ; Mô hình bộ nhớ phẳng và quy ước gọi hàm stdcall
option casemap:none ; Phân biệt chữ hoa chữ thường

; Khai báo thư viện Windows API
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib

.data
    caption_text db "Ket qua kiem tra", 0
    debug_msg db "Bat duoc ngay", 0
    nodebug_msg db "Da thoat", 0

.stack 4096 ; Dành riêng 4096 bytes cho ngăn xếp.
assume fs:nothing ; Cho trình biên dịch biết không đưa giả định gì về thanh ghi FS    

.code ; Bắt đầu phần mã
    main proc ; Thủ tục hàm chính 
        push ebp ; Lưu con trỏ cơ sở cũ
        mov ebp, esp ; Thiết lập khung ngăn xếp mới
        
        ; Truy cập Process Environment Block để kiểm tra BeingDebugged
        mov eax, [fs:30h] ; fs:[0x30] chứa con trỏ đến PEB (Process Environment Block)
        mov al, byte ptr [eax + 02h] ; Truy cập BeingDebugged flag (offset 0x02 trong PEB)
        
        ; Kiểm tra giá trị BeingDebugged
        test al, al
        jz not_debugged
        
        ; Hiển thị thông báo "Bat duoc ngay" nếu đang bị debug
        invoke MessageBox, NULL, addr debug_msg, addr caption_text, MB_OK
        jmp exit_program
        
    not_debugged:
        ; Hiển thị thông báo "Da thoat" nếu không bị debug
        invoke MessageBox, NULL, addr nodebug_msg, addr caption_text, MB_OK
        
    exit_program:
        ; Dọn dẹp và trả về
        mov esp, ebp ; Khôi phục stack pointer
        pop ebp ; Khôi phục ebp cũ
        
        ; Kết thúc chương trình
        invoke ExitProcess, 0
    main endp ; Kết thúc thủ tục chính.
end main ; Kết thúc chương trình, chỉ định điểm vào là thủ tục main