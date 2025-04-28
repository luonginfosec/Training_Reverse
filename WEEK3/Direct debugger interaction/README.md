# Anti-Debug: Direct debugger interaction

## Direct debugger interaction

Những kỹ thuật sau cho phép tiến trình đang chạy tự quản lý giao diện người dùng, hoặc tương tác với tiến trình cha của nó, để phát hiện ra các dấu hiệu bất thường vốn chỉ xuất hiện khi tiến trình đang bị gỡ lỗi.

### 1. Self-Debugging
Có ít nhất ba hàm có thể được dùng để gắn debugger vào một tiến trình đang chạy:

```kernel32!DebugActiveProcess()```
```ntdll!DbgUiDebugActiveProcess()```
```ntdll!NtDebugActiveProcess()```

Vì chỉ có thể có một debugger gắn vào một tiến trình tại một thời điểm, nên nếu việc gắn debugger thất bại, điều đó có thể cho thấy tiến trình đang bị một debugger khác kiểm soát.

Trong ví dụ bên dưới, chúng ta chạy một phiên bản thứ hai của tiến trình, và tiến trình cố gắng gắn debugger vào tiến trình cha (chính là phiên bản thứ nhất)

Nếu ```kernel32!DebugActiveProcess()``` thực hiện thất bại, tiến trình thứ hai sẽ kích hoạt một sự kiện đã được phiên bản thứ nhất tạo ra.

Khi sự kiện này được kích hoạt, phiên bản đầu tiên sẽ hiểu rằng có debugger đang gắn vào.

### 2. GenerateConsoleCtrlEvent()

Khi người dùng nhất Ctrl + C hoặc Ctrl + Break và cửa sổ console đang được chọn (focus), Windows sẽ kiểm tra xem chương trình có đăng ký sự kiện (handler) cho tín hiệu này hay không.

Mặc định, tất cả các tiến trình console đều có một hàm sử lý sẵn, hàm này sẽ gọi ```kernel32!ExitProcess()``` để kết thúc tiến trình.

Tuy nhiên ta có thể đăng ký một handler riêng bỏ qua tín hiệu Ctrl + C hoặc Ctrl + Break này.

Ngoài ra, nếu một tiến trình console đang bị debug và chưa tắt việc nhận tín hiệu Ctrl + C, hệ thống sẽ phát sinh một ngoại lệ (exception) tên là ```DBG_CONTROL_C```

Thông thường, debugger sẽ chặn (intercept) ngoại lệ này.

Nhưng nếu chúng ta tự đăng ký một handler cho exception, thì ta có thể phát hiện ra ngoại lệ ```DBG_CONTROL_C``` này.

Nếu ngoại lệ ```DBG_CONTROL_C``` bị bắt trong handler của chính chúng ta, điều này có thể cho thấy rằng tiến trình đang bị debug.

### 3. BlockInput()

Hàm ```user32!BlockInput()``` có thể chặn toàn bộ sự kiện bàn phím và chuột, tức là làm vô hiệu hóa hoàn toàn việc điều khiển máy - đây là một cách khá hiệu quả để chống debugger.

Trên Windows Vita trở lên, gọi hàm này yêu cầu quyền Administrator.

Ngoài ra, ta còn có thể phát hiện xem nào công cụ nào hook (can thiệp) vào user32!BlockInput() hoặc các hàm chống debug khác hay không.

- Theo thiết kế, BlockInput() chỉ cho phép chặn input một lần duy nhất.
- Nếu gọi lần thứ hai, hàm sẽ trả về FALSE.
- Nếu gọi nhiều lần mà hàm vẫn trả về TRUE, có thể là do một công cụ đang hook hoặc giả mạo hành vi của BlockInput().



### 4. NtSetInformationThread()

Hàm ```ntdll!NtSetInformationThread()``` có thể được dùng để ẩn một luồng (thread) khỏi debugger. 
Bằng cách sử dụng giá trị không được công bố ```THREAD_INFORMATION_CLASS::ThreadHideFromDebugger (0x11)```.

Chức năng này được thiết kế cho một tiến trình khác gọi tới, nhưng thực tế bất kỳ luồng nào cũng có thể tự ẩn chính nó.

Khi luồng bị ẩn khỏi debugger:
Luồng vẫn tiếp tục chạy bình thường.
Tuy nhiên, debugger sẽ không nhận được bất kì sự kiện nào liên quan đến luồng đó nữa.
Luồng ẩn này có thể thực hiện các hành động kiểm tra chống debug, như kiểm tra checksum mã lệnh, hoặc đọc các cờ debug.

Nhưng nếu bạn đặt breakpoint trong luồng đã bị ẩn hoặc nếu ẩn luồng chính của tiến trình thì có thể sẽ bị crash hoặc debugger bị treo.

### 5. EnumWindows() và SuspendThread()

Dò tìm cửa sổ cha của process.
Xem tiêu đề cửa sổ có chữ "debug", "dbg" không.
Nếu có → xác định đó là debugger.
Sau đó suspend (đóng băng) luồng của debugger để ngăn nó hoạt động.


iệt kê tất cả các cửa sổ cấp cao nhất (top-level windows) đang hiện trên màn hình bằng hàm ```EnumWindows()``` (hoặc ```EnumThreadWindows()```) 

Với mỗi cửa sổ, dùng ```GetWindowThreadProcessId()``` để lấy ra Process ID (PID) đang sở hữu cửa sổ đó.

So sánh PID vừa lấy với PID của tiến trình cha. Nếu trùng, tức là cửa sổ đó thuộc về tiến trình cha

Sau đó, dùng ```GetWindowTextW()``` để lấy tiêu đề (title) của cửa sổ đó.
Kiểm tra nội dung tiêu đề xem có giống với tên của một trình gỡ lỗi không (ví dụ như "x64dbg", "OllyDbg", "IDA", "WinDbg", v.v.).

Nếu phát hiện tiêu đề của cửa sổ giống một debugger, thì dùng ```SuspendThread()``` (hoặc ```NtSuspendThread()```) để tạm dừng luồng của tiến trình cha, khiến debugger bị treo và không hoạt động nữa.

### 6. SwitchDesktop()

Windows hỗ trợ nhiều desktop trong một tiến trình (session).
Chúng ta có thể chọn một desktop khác khác desktop hiện hành (active desktop), điều này sẽ ẩn toàn bộ cửa sổ desktop cũ đi và không có cách nào rõ ràng để quay lại desktop cũ.

Thêm nữa các sự kiện chuột và bàn phím từ desktop của tiến trình sẽ không còn được gửi tới debugger, vì desktop đó không còn chia sẻ cùng một nguồn với debugger nữa.
Kết quả là làm cho debugging trở nên bất khả thi.


## Mitigations

Khi đang debug, tốt nhất là bỏ qua các lệnh khả nghi (ví dụ: thay chúng bằng NOPs)

Nếu viết một giải pháp chống lại cơ chế chống debug (anti-anti-debug), tất cả các hàm sau đây đều có thể được hook:

```
kernel32!DebugActiveProcess

ntdll!DbgUiDebugActiveProcess

ntdll!NtDebugActiveProcess

kernel32!GenerateConsoleCtrlEvent()

user32!NtUserBlockInput

ntdll!NtSetInformationThread

user32!NtUserBuildHwndList (dùng để lọc kết quả từ EnumWindows)

kernel32!SuspendThread

user32!SwitchDesktop

kernel32!OutputDebugStringW
```
Các hàm đã được hook có thể kiểm tra tham số đầu vào và thay đổi hành vi gốc của hàm đó.

