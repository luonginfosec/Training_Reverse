# Mẫu sqlite3.dll (sha256 36caddbc06b1725cfa9d49c3c5111f66e09c079091d54bf3f21e6732a461564a)

![alt text](img/1.png)

Nhìn ban đầu mẫu được cung cấp gồm có 3 file. Nhưng thường dll sẽ là nơi chứa mã độc nhất. Còn file ini sẽ là payload hoặc shellcode bị mã hóa gì đó.

# Phân tích tĩnh  

![alt text](img/2.png)

Khi mở file bằng CFF chúng ta thấy dấu hiệu như sau có thể đây là phần mềm hợp pháp được lợi dụng để load dll độc hại như sqlite3.dll. Thử tải phần mềm hợp pháp thông qua trang chủ https://sqlitebrowser[.]org/ và so sánh hash thử. 

![alt text](img/3.png)

Hash giống nhau vậy file exe được cung cấp là phần mềm hợp pháp. 

![alt text](img/4.png)

Vậy dll này là dll độc hại rồi. Sự khác biệt các thể thấy qua hash cũng như dung lượng file dll.

Phần tên file-names cũng khá lạ ```1965627318558789632.x86_64.tmp```.

![alt text](img/6.png)

Thông qua pestudio thấy rất có khả năng mẫu này sẽ có liên quan đến kĩ thuật Process Injection, có kiểm tra Sandbox, máy ảo. Phần entropy khá cao, chứng tỏ có thể có thông tin bị nén.

Sử dụng công cụ floss chúng ta thấy được 1 số strings liên quan như:

- Liên quan đến việc detect sử dụng máy ảo như: 
    - Identifier
    - HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0
    - VMWARE
    - VBOX
    - HARDWARE\Description\System
    - SYSTEM\ControlSet001\Control\SystemInformation
    - HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0
    - HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0
    - SystemBiosVersion
    - VideoBiosVersion
    - VIRTUALBOX
    - SystemBiosDate
    - 06/23/99
    - SystemManufacturer
    - SystemProductName
    - HARDWARE\ACPI\DSDT\VBOX__
    - HARDWARE\ACPI\FADT\VBOX__
    - HARDWARE\ACPI\RSDT\VBOX__
    - SOFTWARE\Oracle\VirtualBox Guest Additions
    - SYSTEM\ControlSet001\Services\VBoxGuest
    - SYSTEM\ControlSet001\Services\VBoxMouse
    - SYSTEM\ControlSet001\Services\VBoxService
    - SYSTEM\ControlSet001\Services\VBoxSF
    - SYSTEM\ControlSet001\Services\VBoxVideo

Hai bài viết hữu dụng khi nói đến việc này là:

- https://medium.com/@everythingBlackkk/how-does-malware-know-difference-between-the-virtual-machine-and-the-real-machine-b44b0eb45584

- https://unprotect.it/technique/detecting-virtual-environment-artefacts/

Sử dụng IDA để phân tích, chúng ta vào ngay phần Exports

![alt text](img/8.png)

Chúng ta thấy có 1 loại hàm giống nhau, chúng chỉ là những hàm giả, đánh lừa để load dll được thành công khi phần mềm hợp pháp load. Các hàm cách nhau 0x10 bytes và chúng đơn giản chỉ return lại 1. 

![alt text](img/9.png)

Nhờ vậy chúng ta bỏ qua các hàm không phân tích, khá may mắn, vì nếu không thì phải đi check khá tuần tự. 

Nhờ strings chúng ta cũng tìm thấy nơi chứa hàm AntiVM. 

![alt text](img/7.png)

| Rule | Root | RegPath | ValueName | Needle (chuỗi cần chứa) | Mục đích / Ý nghĩa |
|---:|---|---|---|---|---|
| 1 | HKLM | `HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0` | `Identifier` | `VMWARE` | Detect VMware qua định danh thiết bị SCSI (port 0). |
| 2 | HKLM | `HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0` | `Identifier` | `VMWARE` | Detect VMware qua SCSI (port 1). |
| 3 | HKLM | `HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0` | `Identifier` | `VMWARE` | Detect VMware qua SCSI (port 2). |
| 4 | HKLM | `HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0` | `Identifier` | `VBOX` | Detect VirtualBox qua định danh thiết bị SCSI (port 0). |
| 5 | HKLM | `HARDWARE\Description\System` | `SystemBiosVersion` | `VBOX` | Detect VirtualBox qua chuỗi trong BIOS version. |
| 6 | HKLM | `HARDWARE\Description\System` | `VideoBiosVersion` | `VIRTUALBOX` | Detect VirtualBox qua chuỗi trong Video BIOS version. |
| 7 | HKLM | `HARDWARE\Description\System` | `SystemBiosDate` | `06/23/99` | Heuristic: BIOS date đặc trưng của một số VM/sandbox image. |
| 8 | HKLM | `SYSTEM\ControlSet001\Control\SystemInformation` | `SystemManufacturer` | `VMWARE` | Detect VMware qua hãng máy (Manufacturer). |
| 9 | HKLM | `SYSTEM\ControlSet001\Control\SystemInformation` | `SystemProductName` | `VMWARE` | Detect VMware qua tên sản phẩm/model (ProductName). |

![alt text](img/10.png)

Nếu có trường tồn tại và có giá trị thỏa mãn bao gồm constant_str nó sẽ trả về 1. 

![alt text](img/11.png)

Patch lại cho return 0 hết.

Sau 1 lúc để ý chúng ta thấy hàm sqlite3_config có dấu hiệu khác lạ nhất. Tiến hành phân tích. Đây chính là hàm mã độc mà chúng ta cần tìm. 

![alt text](img/13.png)

Phân tích đối với hàm init.

![alt text](img/14.png)

![alt text](img/15.png)

Chức năng của hàm này sau một hồi chúng ta phải tạo struct và tính hash với công cụ hashdb. Thấy được rõ chức năng của hàm này là resolve các hàm thông qua việc giải các api hasing đã được define từ trước.

Tiếp tục đến với hàm inject.

![alt text](img/17.png)

![alt text](img/18.png)

Quy trình là nó sẽ giải mã payload đã được define trước với key có sẵn.

Đây là payload.
![alt text](img/19.png)

Đây là key. 
![alt text](img/20.png)

Giải mã RC4.

[RC4_Script](script/rc4.py)

![alt text](img/21.png)

Rõ ràng vậy là nó lấy đường dẫn đầy đủ của dll + thêm phần đến file crashdump.ini. Rõ ràng sau đó tại hàm get_data nó thực hiện việc đọc file và giải mã ra shellcode.

![alt text](img/22.png)

Nó thực hiện việc mem_copy shellcode qua vùng nhớ rồi dùng VirtualProtect và GrayStringA để đổi quyền của vùng nhớ và thực thi shellcode.

![alt text](img/23.png)

Khá thú vị là ở đây mã độc sử dụng hàm ```GrayStringA``` để chạy shellcode thông qua lpOutputFunc (callback function).

Tiếp theo mục tiêu của chúng ta sẽ là dump shellcode ra xem nó là gì. Đến bước này thì đơn giản nhất là sử dụng debug thui.

# Phân tích động

Cấu hình IDA như hình.

![alt text](img/24.png)

![alt text](img/25.png)

Hàm mem_copy nhận vào 3 tham số lần lượt thông qua rcx, rdx, r8. 

Vậy ở bước này rdx chính là nơi chúng ta cần lấy dữ liệu với len là thanh ghi r8. Sử dụng script để dump vùng nhớ đó ra. 

[Dump_Script](script/dump.py)

![alt text](img/26.png)

Dump thành công.

Sử dụng công cụ https://github.com/jstrosch/sclauncher để chuyển đổi shellcode thành PE files để tiến hành công việc debug tiếp.

Bài viết tham khảo:
- https://www.thecyberyeti.com/post/analyzing-shellcode-with-sclauncher

![alt text](img/27.png)

Chuyển đổi thành công, công việc tiếp theo là debug để xác định hành vi của shellcode này. 

![alt text](img/27.png)

# Phân tích shellcode: stage 2

![alt text](img/28.png)

Tiếp tục sử dụng IDA để phân tích shellcode, thấy được chương trình này đã giải mã ra một dll và sử dụng hàm LoadLibraryA để load nó ra. Tiến hành dump dll ra để phân tích.

# Phân tích dll

![alt text](img/29.png)

Mã độc nằm ở hàm main của dll gồm 4 chức năng lớn như hình.

![alt text](img/30.png)

Trong hàm func_resolve_and_create_data đầu tiên có resolve rất nhiều hàm của kernel32, ntdll và trong vftable cũng resolve rất nhiều hàm của các thư viện.

![alt text](img/31.png)

Có cả việc lấy thông tin version của OS nhờ dùng bằng RtlGetVersion.

![alt text](img/32.png)


Tiến hành giải mã các dữ liệu cần thiết như: 

```
C:\\Windows\\System32\\Werfault.exe
C:\\Windows\\SysWOW64\\Werfault.exe
POST
69.166.223.19
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Code/1.94.2
Accept: application/javascript, */*; q=0.01
Content-Type: application/json
Connection: keep-alive
Accept-Encoding: gzip, deflate, br
Origin: https://www.notion.so
/react/18.2.0/react-dom.production.min.js
/axios/1.6.8/axios.min.js
/lodash/4.17.21/lodash.min.js
/moment/2.29.4/moment.min.js
/extensions/vuejs.vue-3.4.21
/extensions/apollographql.apollo-client-3.7.10
/extensions/chartjs.chart-4.4.0
```

![alt text](img/33.png)

Ở đây nó thực hiện kĩ thuật Direct System Calls để gọi các hàm nó muốn, cũng như né tránh các trình theo dõi hệ thống.

![alt text](img/34.png)

Tiếp tục là func_get_info

![alt text](img/35.png)

Nó tiến hành khởi tạo cơ chế mã hóa phiên C2 ngẫu nhiên trong việc giao tiếp.

![alt text](img/36.png)

Tiếp tục là các hàm liên quan đến việc lấy thông tin người dùng như:

```
shellcode_struct->GetComputerNameExA(0, v10); // Lấy tên máy (NetBIOS)
shellcode_struct->GetUserNameA(v14);          // Lấy tên người dùng hiện tại
shellcode_struct->GetComputerNameExA(2, v18); // Lấy tên máy (DNS Hostname)
```

Thu thập Cấu hình Mạng và Địa chỉ IP

![alt text](img/37.png)

Lấy các thông tin liên quan đến tiến trình, luồng, OS máy thông qua TEB.

![alt text](img/38.png)

Tiếp theo là hàm command_control ở đây nó thực hiện việc kết nối, cũng như nhận các lệnh từ C2 để thực hiện các hành vi của nó. Còn tự xác định cấu hình proxy của máy để giúp việc kết nối ra ngoài vượt mặt các cấu hình tưởng lửa nhờ sử dụng WinHttpGetIEProxyConfigForCurrentUser và WinHttpGetProxyForUrl.

![alt text](img/39.png)

![alt text](img/41.png)

Thiết lập WinHttpSetOption giúp bỏ qua các chứng chỉ.

![alt text](img/40.png)

Thực hiện mã giải, giải mã các thông tin nhận được khiến cho việc phân tích khó khăn hơn qua w_xor_data và math_0. Sau đó tiến hành so sánh để kiểm tra xem có phải đúng là dữ liệu từ server thật của hacker không tránh bị phân tích bằng các công cụ phân tích tự động.  

Tiếp đến là hàm quan trọng step2()

![alt text](img/42.png)

Ở đây nó thực hiện việc duy trì kết nối, cũng như việc nhận và thực thi các hành vi.
Nó cũng thực hiện việc kiểm tra thời gian hiện tại và tiến hành so sánh, nếu thỏa mãn với cấu hình thì nó mới tiếp tục chạy.

Thực hiện đổi tiến trình từ Thread sang Fiber nhằm né tránh các trình theo dõi, cũng như làm giảm phần trăm CPU khiến cho việc phát hiện trở nên khó khăn hơn. Do Fiber cũng ở tầng user-mode nữa.

![alt text](img/43.png)

Tiếp đó nó thực hiện giải mã dữ liệu và thực thi các chức năng tương ứng đối với vftable_02.

![alt text](img/44.png)

f_func_get_info: thu thập thông tin nhằm mục đích thăm dò, định danh

f_net_enum: dò quét các tài nguyên mạng trong mạng LAN, các ổ đĩa, thư mục chia sẻ, và danh sách người dùng trong domain.

f_Process: thực hiện hành vi liệt kê các tiến trình đang chạy, lấy thông tin về đường dẫn cũng như quyền hạn thực thi của chúng.

f_end_process_thread: dừng một tiến trình hoặc luồng cụ thể đang chạy trên máy nạn nhân.

f_ProcessToken: thực hiện đánh cắp token của tiến trình nhằm mục đích leo thang đặc quyền.

f_f_writememory: thực hiện ghi dữ liệu vào 1 tiến trình khác (process injection)

Các hàm như f_process_wefault_0 và f_process_wefault_1 thực hiện kĩ thuật tiêm mã vào WerFault.exe giúp chạy mã độc dưới 1 tiến trình hợp pháp của Windows.

f_Lsa: đánh cắp token của tiến trình lsass.exe nhằm mục đích leo thang đặc quyền. Cũng như sử dụng để đánh cắp mật khẩu ở dạng rõ cũng như dạng hash.

Các hàm như f_load_NET và f_execute_NET cho phép mã độc nạp trực tiếp các file ```.dll``` hoặc ```.exe``` hợp pháp viết bằng ngôn ngữ .NET và thực thi.

f_file_persistent: đọc, ghi, xóa, di chuyển thiết lập cơ chế persistence.

f_read_write_pipe: giao tiếp giữa mạng và tiến trình thông qua Named Pipe.

f_socket: tạo các kết nối mạng mới.

f_w_screenshot: chụp ảnh màn hình.


