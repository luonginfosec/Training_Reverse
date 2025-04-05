# WEEK 1 by luongvd

## Tìm hiểu thuật toán mã hóa RC4

### Sơ bộ

- Thuật toán mã hóa RC4 (**Rivest Cipher 4**) là một thuật toán mã hóa dòng (**stream cipher**) do **Ron Rivest** phát triển vào năm 1987 và từng được sử dụng rộng rãi. Tuy nhiên, do tồn tại một số lỗ hổng bảo mật, RC4 không còn được sử dụng phổ biến và đã có các thuật toán thay thế an toàn hơn.

### Nguyên lí hoạt động

![alt text](./WEEK1/RC4.png)

- RC4 hoạt động dựa trên nguyên tắc phát sinh **chuỗi khóa (keystream)** và thực hiện phép **XOR** với **dữ liệu gốc (plaintext)** để tạo ra **dữ liệu mã hóa (ciphertext)**.
- Quá trình mã hóa và giải mã của RC4 hoàn toàn giống nhau, chỉ cần thực hiện XOR với cùng một keystream.
- Thuật toán gồm hai bước chính:
  - **Khởi tạo trạng thái** (**KSA - Key Scheduling Algorithm**)
  - **Tạo chuỗi khóa** (**PRGA - Pseudo-Random Generation Algorithm**)
- Bản chất : RC4 là một loại khóa dòng, phép mã hóa và giải mã được thực hiện với thuật toán tương tự nhau, với key được gen qua hai bước hoán vị là KSA và PRGA
---

## Chi tiết thuật toán

### Bước 1: Khởi tạo trạng thái (KSA - Key Scheduling Algorithm)

1. **Khởi tạo mảng trạng thái `S`** với 256 phần tử, giá trị ban đầu từ `S[0]` đến `S[255]` là **0, 1, 2, ..., 255**.
2. **Khởi tạo mảng tạm `T`** từ khóa đầu vào `key`, bằng cách lặp lại khóa đến khi đủ **256 bytes**.
3. **Thực hiện hoán vị các phần tử trong `S`** dựa trên giá trị của `T`, giúp trộn lẫn mảng trạng thái:

   ```c
   j = (j + S[i] + T[i]) % 256;
   swap(S[i], S[j]);
   ```

---

### Bước 2: Sinh chuỗi khóa (PRGA - Pseudo-Random Generation Algorithm)

1. **Dùng mảng `S` để sinh ra một luồng byte ngẫu nhiên**.
2. **Với mỗi byte dữ liệu đầu vào, tạo ra chỉ số `i` và `j`**:
   
   ```c
   i = (i + 1) % 256;
   j = (j + S[i]) % 256;
   swap(S[i], S[j]);
   ```

3. **Lấy giá trị trong bảng `S` để tạo byte keystream**:
   
   ```c
   key_byte = S[(S[i] + S[j]) % 256];
   ```

4. **Mã hóa dữ liệu bằng phép XOR**:
   
   ```c
   C = P ⊕ key_byte;
   ```
   - `C` là byte mã hóa.
   - `P` là byte plaintext.
   - `key_byte` là byte từ keystream.


### Code minh họa

[Source code ở đây](./WEEK1/RC4.py)
```Python
def KSA(key):
    S = list(range(256))
    T = [key[i % len(key)] for i in range(256)]
    j = 0
    for i in range(256):
        j = (j + S[i] + T[i]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def PRGA(S, data_length):
    i = 0
    j = 0
    keystream = []
    for _ in range(data_length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        key_byte = S[(S[i] + S[j]) % 256]
        keystream.append(key_byte)
    return keystream

def RC4_encrypt_decrypt(key, data):
    key = [ord(c) for c in key]
    S = KSA(key)
    keystream = PRGA(S, len(data))
    result = bytes(d ^ k for d, k in zip(data, keystream))
    return result

def input_data():
    key = input("Nhập key: ")
    plaintext = input("Nhập plaintext: ").encode()
    return key, plaintext

def output_result(ciphertext, decrypted):
    print("Ciphertext (hex):", ciphertext.hex())
    print("Decrypted text:", decrypted.decode())

if __name__ == "__main__":
    key, plaintext = input_data()
    ciphertext = RC4_encrypt_decrypt(key, plaintext)
    decrypted = RC4_encrypt_decrypt(key, ciphertext)
    output_result(ciphertext, decrypted)
```

[Source code ở đây](./WEEK1/RC4.c)
```C
#include <stdio.h>
#include <string.h>

void swap(unsigned char *a, unsigned char *b) {
    unsigned char temp = *a;
    *a = *b;
    *b = temp;
}

void ksa(unsigned char *S, unsigned char *key, int key_len) {
    int i, j = 0;
    for (i = 0; i < 256; i++) {
        S[i] = i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        swap(&S[i], &S[j]);
    }
}

void prga(unsigned char *S, unsigned char *plaintext, unsigned char *ciphertext, int len) {
    int i = 0, j = 0, k;
    for (k = 0; k < len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        swap(&S[i], &S[j]);
        int t = (S[i] + S[j]) % 256;
        ciphertext[k] = S[t] ^ plaintext[k];
    }
}

void rc4_encrypt(unsigned char *plaintext, unsigned char *key, int plaintext_len, int key_len, unsigned char *ciphertext) {
    unsigned char S[256];
    ksa(S, key, key_len);
    prga(S, plaintext, ciphertext, plaintext_len);
}

void print_hex(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}
int main() {
    unsigned char plaintext[256];
    unsigned char key[256];
    
    printf("Nhap plaintext: ");
    fgets((char *)plaintext, sizeof(plaintext), stdin);
    plaintext[strcspn((char *)plaintext, "\n")] = 0;
    
    printf("Nhap key: ");
    fgets((char *)key, sizeof(key), stdin);
    key[strcspn((char *)key, "\n")] = 0;
    
    int plaintext_len = strlen((char *)plaintext);
    int key_len = strlen((char *)key);
    
    unsigned char ciphertext[plaintext_len];
    
    rc4_encrypt(plaintext, key, plaintext_len, key_len, ciphertext);
    
    printf("Plaintext: %s\n", plaintext);
    printf("Key: %s\n", key);
    printf("Ciphertext (hex): ");
    print_hex(ciphertext, plaintext_len);
    
    return 0;
}
```

## Code MASM

```
Code thuật toán mã hóa RC4 bằng asm x86
- Nghiên cứu, giải thích thuật toán
- Input: Plain Text + Key
- Output: Hex
- Code tổ chức, comment rõ ràng từng dòng
- Không dùng bất cứ thư viện có sẵn nào, kiểu invoke, hay printf, hay scan, tất cả chỉ được dùng WinAPI, Call WriteConsole call ReadConsole truyền tham số bằng push stack, atoi, itoa tất cả code chay
```
    
[Source code ở đây](./WEEK1/asm.asm)
```asm
.386	; Chỉ định sử dụng bộ xử lí Intel 80386 trở lên
.model flat, stdcall	; Mô hình bộ nhớ phẳng và quy ước gọi hàm stdcall
option casemap:none		; Không phân biệt chữ hoa chữ thường trong tên biến/hàm.

include \masm32\include\windows.inc ; Bao gồm các định nghĩa Window API
include \masm32\include\kernel32.inc ; Bao gồm các định nghĩa với Kernel32 API
includelib \masm32\lib\kernel32.lib	; Liên kết với thư viện Kernel32


.data ; Phần khai báo dữ liệu
	BUFFER_SIZE EQU 1024 ; Định nghĩa hằng số BUFFER_SIZE là 1024 bytes
	S_SIZE EQU 256 ; Định nghĩa kích thước mảng S là 256 bytes (dùng trong RC4)

	inHandle DD 0 ; Biến lưu handle đầu vào chuẩn (console input)
	outHandle DD 0 ; Biến lưu handle đầu ra chuẩn (console output) 
	bytesRead DD 0	; Số byte đã đọc từ input
	bytesWritten DD 0 ; Số byte đã ghi ra output
	
	promptText DB "Input plaintext: ", 0 ; Chuỗi nhắc nhập văn bản gốc
	promptTextLen DD $ - promptText ; Độ dài chuỗi nhắc ($ là địa chỉ hiện tại)
	promptKey DB "Input key: ", 0 ; Chuỗi nhắc nhập khóa
	promptKeyLen DD $ - promptKey ; Độ dài chuỗi khóa
	outputPrompt    DB "Ciphertext (HEX): ", 0 ; Chuỗi nhắc xuất kết quả
    outputPromptLen DD $ - outputPrompt        ; Độ dài chuỗi nhắc xuất

	textBuffer DB BUFFER_SIZE DUP(0) ; Buffer lưu văn bản gốc
	textLen DD 0 ; Độ dài văn bản gốc
	keyBuffer DB BUFFER_SIZE DUP(0) ; Buffer lưu khóa
	keyLen DD 0 ; Độ dài khóa
	cipherBuffer DB BUFFER_SIZE DUP(0) ; Buffer lưu văn bản đã mã hóa
	hexBuffer DB BUFFER_SIZE*3 DUP(0) ; Buffer lưu dạng hex của văn bản mã hóa.


	S DB S_SIZE DUP(0) ; Mảng S của thuật toán RC4
	hexChars       DB "0123456789ABCDEF", 0    ; Các ký tự hex để chuyển đổi
    newLine        DB 0Dh, 0Ah                 ; Ký tự xuống dòng (CR+LF)

.code
main PROC 
	push STD_INPUT_HANDLE	; Đẩy hằng số STD_HANDLE vào stack
	call GetStdHandle	; Gọi hàm GetStdHandle để lấy handle đầu vào chuẩn
	mov inHandle, eax	; Lưu handle vaof biến inHandle (eax chứa giá trị trả về)

	push STD_OUTPUT_HANDLE	; Đẩy hằng số STD_OUTPUT_HANDLE vào stack
	call GetStdHandle	; Gọi hàm GetStdHandle để lấy handle đầu ra chuẩn
	mov outHandle, eax	; Lưu handle vào biến outHandle

	call getInput ; https://learn.microsoft.com/en-us/windows/console/getstdhandle Gọi thủ tục để nhập dữ liệu
	call KSA ; Gọi thủ tục KSA (Key Scheduling Algorithm) của RC4
	call PRGA_and_XOR        ; Gọi thủ tục PRGA (Pseudo-Random Generation Algorithm) và XOR
	call showOutput          ; Gọi thủ tục showOutput để hiển thị kết quả
	push 0
	call ExitProcess
main ENDP


	
getInput PROC
	COMMENT !
		======CODE MINH HỌA TƯƠNG TỰ======
		unsigned char plaintext[1024];
		unsigned char key[1024];
    
		printf("Nhap plaintext: ");
		fgets((char *)plaintext, sizeof(plaintext), stdin);
		plaintext[strcspn((char *)plaintext, "\n")] = 0;
    
		printf("Nhap key: ");
		fgets((char *)key, sizeof(key), stdin);
		key[strcspn((char *)key, "\n")] = 0;
    
		int plaintext_len = strlen((char *)plaintext);
		int key_len = strlen((char *)key);
		https://learn.microsoft.com/en-us/windows/console/writeconsole
		https://learn.microsoft.com/en-us/windows/console/readconsole
	!
    push 0                  ; Tham số lpReserved (không sử dụng)
    lea eax, bytesWritten   ; Nạp địa chỉ của bytesWritten vào eax
    push eax                ; Đẩy địa chỉ của bytesWritten vào stack
    push promptTextLen      ; Đẩy độ dài chuỗi nhắc vào stack
    push OFFSET promptText  ; Đẩy địa chỉ của chuỗi nhắc vào stack
    push outHandle          ; Đẩy handle đầu ra vào stack
    call WriteConsole       ; Gọi hàm WriteConsole để hiển thị chuỗi nhắc Input plaintext: 

	push 0  ; Tham số lpReserved (không sử dụng)
	lea eax, bytesRead ; Nạp địa chỉ của bytesRead vào eax
	push eax ; Đẩy địa chỉ của bytesRead vào stack 
	push BUFFER_SIZE - 1 ; Đẩy kích thước tối đa có thể đọc vào stack
	push OFFSET textBuffer ; Đẩy địa chỉ của buffer vào stack
	push inHandle ; Đẩy handle đầu vào stack
	call ReadConsole ; Gọi hàm ReadConsole để đọc văn bản gốc.

	mov ecx, bytesRead ; Nạp số bytes đã đọc vào ecx
	sub ecx, 2 ; Trừ đi 2 (bỏ ký tự CR+LF ở cuối)
	mov textLen, ecx ; Lưu độ dài thực của văn bản
	mov byte ptr [textBuffer + ecx], 0 ; Thêm kí tự null vào cuối

	push 0                  ; Tham số lpReserved (không sử dụng)
    lea eax, bytesWritten   ; Nạp địa chỉ của bytesWritten vào eax
    push eax                ; Đẩy địa chỉ của bytesWritten vào stack
    push promptKeyLen      ; Đẩy độ dài chuỗi nhắc vào stack
    push OFFSET promptKey  ; Đẩy địa chỉ của chuỗi nhắc vào stack
    push outHandle          ; Đẩy handle đầu ra vào stack
    call WriteConsole       ; Gọi hàm WriteConsole để hiển thị chuỗi nhắc Input key: 

	push 0  ; Tham số lpReserved (không sử dụng)
	lea eax, bytesRead ; Nạp địa chỉ của bytesRead vào eax
	push eax ; Đẩy địa chỉ của bytesRead vào stack 
	push BUFFER_SIZE - 1 ; Đẩy kích thước tối đa có thể đọc vào stack
	push OFFSET keyBuffer ; Đẩy địa chỉ của buffer vào stack
	push inHandle ; Đẩy handle đầu vào stack
	call ReadConsole ; Gọi hàm ReadConsole để đọc văn bản gốc.

	mov ecx, bytesRead ; Nạp số bytes đã đọc vào ecx
	sub ecx, 2 ; Trừ đi 2 (bỏ ký tự CR+LF ở cuối)
	mov keyLen, ecx ; Lưu độ dài thực của văn bản
	mov byte ptr [keyBuffer + ecx], 0 ; Thêm kí tự null vào cuối
	
	ret ; Trả về từ thủ tục
getInput ENDP ; Kết thúc thủ tục getInput

KSA PROC ; Thủ tục Key Scheduling Algorithm của RC4
	COMMENT !
		======CODE MINH HỌA TƯƠNG TỰ======
	void ksa(unsigned char *S, unsigned char *key, int key_len) {
		int i, j = 0;
		for (i = 0; i < 256; i++) {
			S[i] = i;
		}
		for (i = 0; i < 256; i++) {
			j = (j + S[i] + key[i % key_len]) % 256;
			swap(&S[i], &S[j]);
		}
	}	
	!
	mov ecx, 0 ; Khởi tạo biến đếm ecx  = 0

init_S: ; Phần khởi tạo mảng S
	mov byte ptr [S + ecx], cl ; Gán S[i] = i (cl là byte thấp của ecx)
	inc ecx ; Tăng biến đếm
	cmp ecx, S_SIZE ; So sánh với kích thước của mảng S
	jl init_S ; Nếu nhỏ hơn thì tiếp tục vòng lặp 

	mov ecx, 0 ; Khởi tạo biến đếm i = 0 (ecx = 0)
	mov ebx, 0 ; Khởi tạo biến j = 0 (ebx = 0)
	mov esi, 0 ; Khởi tạo biến tạm (esi = 0)
	
scramble_S: ; Xáo trộn mảng S
	mov al, byte ptr [S + ecx] ; Lấy giá trị S[i] vào al (eax)
	add ebx, eax ; j = j + S[i]

	mov eax, ecx ; Nạp i vào eax (EDX:EAX)            
    mov edx, 0 ; Xóa edx để chuẩn bị phép chia
    div keyLen  ; Chia i cho độ dài khóa, phần dư lưu trong edx
    mov esi, edx  ; Lưu phần dư vào esi (esi = i % keyLen)

	movzx eax, byte ptr [keyBuffer + esi] ; Lấy giá trị key[i % keyLen] vào eax
	add ebx, eax ; j = j + key[i % keyLen]
	and ebx, 0FFh ; j = j % 256 (giữ j trong khoảng 0 - 255)

	mov al, byte ptr [S + ecx] ; Lấy giá trị S[i] vào al
	mov dl, byte ptr [S + ebx] ; Lấy giá trị S[j] vào dl
	mov byte ptr [S + ecx], dl ; S[i] = S[j]
	mov byte ptr [S + ebx], al ; S[j] = S[i] (hoán đổi giá trị S[i] và S[j])
	
	inc ecx ; Tăng biến đếm i 
	cmp ecx, S_SIZE
	jl scramble_S ; Nếu nhỏ hơn thì tiếp tục vòng lặp
	ret ; Trả về từ thủ tục
KSA ENDP

PRGA_and_XOR PROC ; Thủ tục Pseudo-Random Generation Algorithm và XOR
	COMMENT !
		======CODE MINH HỌA TƯƠNG TỰ======
	void prga(unsigned char *S, unsigned char *plaintext, unsigned char *ciphertext, int len) {
		int i = 0, j = 0, k;
		for (k = 0; k < len; k++) {
			i = (i + 1) % 256;
			j = (j + S[i]) % 256;
			swap(&S[i], &S[j]);
			int t = (S[i] + S[j]) % 256;
			ciphertext[k] = S[t] ^ plaintext[k];
		}
	}
	!
	mov ecx, 0 ; Khởi tạo biến i  = 0
	mov ebx, 0 ; Khởi tạo biến j = 0
	mov edi, 0 ; Khởi tạo biến đếm
encrypt_loop: ; Nhãn vòng lặp
	cmp edi, textLen ; So sánh với độ dài văn bản
	jge encrypt_done ; Nhảy nếu lớn hơn hoặc bằng 

	inc ecx ; i = i + 1
	and ecx, 0FFh ; i =  i % 256

	movzx eax, byte ptr [S + ecx] ; Lấy giá trị S[i] vào eax
	add ebx, eax ; j = j + S[i]
	and ebx, 0FFh ; j = j % 256

	mov al, byte ptr [S + ecx] ; Lấy giá trị S[i] = al
	mov dl, byte ptr [S + ebx] ; Lấy giá trị S[j] vào edx
	add eax, edx ; eax = S[i] + S[j]
	and eax, 0FFh ; eax = (S[i] + S[j]) % 256
	movzx eax, byte ptr [S + eax] ; Lấy giá trị S[(S[i] + S[j]) % 256] vào eax

	xor al, byte ptr [textBuffer + edi] ; Xor với byte văn bản gốc
	mov byte ptr [cipherBuffer + edi], al ; Lưu kết quả vào buffer mã hóa

	inc edi 
	jmp encrypt_loop
encrypt_done:               ; Nhãn kết thúc mã hóa
    ret                     ; Trả về từ thủ tục
PRGA_and_XOR ENDP ; Kết thúc thủ tục PRGA_and_XOR

showOutput PROC ; Thủ tục hiện thị kết quả

	push 0                  ; Tham số lpReserved (không sử dụng)
    lea eax, bytesWritten   ; Nạp địa chỉ của bytesWritten vào eax
    push eax                ; Đẩy địa chỉ của bytesWritten vào stack
    push outputPromptLen    ; Đẩy độ dài chuỗi nhắc xuất vào stack
    push OFFSET outputPrompt  ; Đẩy địa chỉ của chuỗi nhắc xuất vào stack
    push outHandle          ; Đẩy handle đầu ra vào stack
    call WriteConsole       ; Gọi hàm WriteConsole để hiển thị chuỗi nhắc xuất
	
	mov esi, 0 ; Khởi tạo biến đếm vị trí trong buffer mã hóa
	mov edi, 0 ; Khởi tạo biến đếm vị trí trong buffer hex

convert_hex:
	cmp esi, textLen ; So sánh với độ dài văn bản
	jge convert_done ; Nếu đã sử lý hết thì kết thúc.

	movzx eax, byte ptr [cipherBuffer + esi] ; Lấy byte mã hóa vào eax

	mov ecx, eax ; Sao chép giá trị vào ecx
	shr ecx, 4 ; Dịch phải 4 bit để lấy 4 bit cao
	and ecx, 0Fh ; Giữ lại 4 bit thấp (0- 15)
	mov cl, byte ptr [hexChars + ecx] ; Lấy kí tự hex tương ứng
	mov byte ptr [hexBuffer + edi], cl ; Lưu vào buffer hex

	mov ecx, eax ; Sao chép giá trị vào ecx
	and ecx, 0Fh ; Giữ lại 4 bit thấp (0 - 15)
	mov cl, byte ptr [hexChars + ecx] ; Lấy kí tự hex tương ứng
	mov byte ptr [hexBuffer + edi + 1], cl ; Lưu vào buffer hex

	mov byte ptr [hexBuffer + edi + 2], ' ' ; Thêm dấu cách

	inc esi 
	add edi,3
	jmp convert_hex

convert_done:               ; Nhãn kết thúc chuyển đổi
    
    push 0                  ; Tham số lpReserved (không sử dụng)
    lea eax, bytesWritten   ; Nạp địa chỉ của bytesWritten vào eax
    push eax                ; Đẩy địa chỉ của bytesWritten vào stack
    push edi                ; Đẩy số byte cần ghi (độ dài chuỗi hex) vào stack
    push OFFSET hexBuffer   ; Đẩy địa chỉ của buffer hex vào stack
    push outHandle          ; Đẩy handle đầu ra vào stack
    call WriteConsole       ; Gọi hàm WriteConsole để hiển thị chuỗi hex
    
    push 0                  ; Tham số lpReserved (không sử dụng)
    lea eax, bytesWritten   ; Nạp địa chỉ của bytesWritten vào eax
    push eax                ; Đẩy địa chỉ của bytesWritten vào stack
    push 2                  ; Đẩy độ dài chuỗi xuống dòng (2 byte) vào stack
    push OFFSET newLine     ; Đẩy địa chỉ của chuỗi xuống dòng vào stack
    push outHandle          ; Đẩy handle đầu ra vào stack
    call WriteConsole       ; Gọi hàm WriteConsole để hiển thị chuỗi xuống dòng
    
    ret                     ; Trả về từ thủ tục
showOutput ENDP             ; Kết thúc thủ tục showOutput

END main 
```

