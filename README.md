# NT219.R11.ANTN — Lab 02: AES

Bài làm C++ cho AES và các modes, kèm biên dịch thư viện và triển khai sang Python/container. Phần thuật toán chỉ dùng thư viện chuẩn C++, không phụ thuộc OpenSSL hay Crypto++.

## Cấu trúc bài làm

| Task | Source | Nội dung |
| --- | --- | --- |
| 1 | `AES.cpp` | AES-128/192/256 độc lập, có `main()` kiểm tra mã hóa và giải mã. |
| 2 | `modes/include/`, `modes/src/`, `modes/tests/main.cpp` | AES và các modes; đối chiếu kết quả với test vector chuẩn. |
| 3 | `task3/main.cpp` | Cùng một chương trình C++ được liên kết riêng với thư viện tĩnh và thư viện động. |
| 4 | `task4/`, `Dockerfile` | Python gọi thư viện C++ qua C ABI/`ctypes`; đóng gói và chạy trong container. |

```text
AES.cpp
CMakeLists.txt
modes/
  CMakeLists.txt
  include/          # API C++ và C ABI (aes_c.h)
  src/              # AES, các modes và phần triển khai C ABI (aes_c.cpp)
  tests/            # Known-answer tests và kiểm tra C ABI
  cmake/            # Cấu hình package khi cài đặt thư viện
task3/
  main.cpp          # Chương trình dùng thư viện tĩnh/động
task4/
  aes_modes.py      # Binding ctypes, không triển khai lại thuật toán
  main.py           # Chạy kiểm tra thư viện C++ từ Python
Dockerfile
.dockerignore
.gitignore
README.md
```

Chỉ có hai `CMakeLists.txt`: file gốc điều phối toàn bài, file trong `modes/` xây dựng và cài đặt thư viện. `AES.cpp` là chương trình độc lập của Task 1; `modes/src/aes.cpp` là AES dùng chung cho thư viện, không chứa `main()`.

Repo không chứa source Python gốc/file tham khảo của thầy, ảnh tài liệu, file build hay binary. Các chương trình trong `task3/` và `task4/` là phần thực hiện yêu cầu bài, không phải thư mục code mẫu không sử dụng.

## Yêu cầu

- Compiler hỗ trợ C++17, CMake >= 3.16 và công cụ build tương ứng, chẳng hạn GNU Make trên Linux.
- Python 3 cho Task 4; chỉ dùng thư viện chuẩn Python, không cần `pip install`.
- Podman hoặc Docker nếu chạy container.

Các lệnh bên dưới chạy từ thư mục gốc repo, trên Linux.

## Build toàn bộ

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DAES_LIBRARY_TYPE=BOTH
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

`AES_LIBRARY_TYPE` nhận `STATIC`, `SHARED` hoặc `BOTH` (mặc định `STATIC`). Dùng `BOTH` như trên để có đủ hai dạng thư viện cho Task 3 và thư viện động cho Task 4.

CTest chạy các kiểm tra AES, modes và C ABI. Các chương trình dưới đây in output để chụp minh chứng từng task.

## Task 1 — AES

```sh
./build/AES
```

In ba Known-Answer Test cho AES-128, AES-192 và AES-256, gồm `Key`, `Plaintext`, `Expected`, `Computed`, `Decrypted`, `Encrypt` và `Decrypt`. Kết quả đúng khi ciphertext tính được khớp ciphertext chuẩn, giải mã khôi phục plaintext và cả hai phép kiểm tra đều `PASS`.

Thuật toán theo [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf).

## Task 2 — Modes và các cơ chế liên quan

| Đặc tả | Thành phần |
| --- | --- |
| [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) | ECB, CBC, CFB, OFB, CTR |
| [NIST SP 800-38B](https://csrc.nist.gov/pubs/sp/800/38/b/upd1/final) | CMAC |
| [NIST SP 800-38C](https://csrc.nist.gov/pubs/sp/800/38/c/upd1/final) | CCM |
| [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) | GCM, GMAC |
| [NIST SP 800-38E](https://csrc.nist.gov/pubs/sp/800/38/e/final) | XTS |
| [NIST SP 800-38F](https://csrc.nist.gov/pubs/sp/800/38/f/final) | KW, KWP |
| [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452.html) | GCM-SIV |

```sh
./build/modes/aes_tests
```

Kết quả thành công kết thúc bằng `ALL 18 VECTORS PASS`. Đây là **18 mục kiểm tra**, không phải 18 mode; một số mục kiểm tra riêng ciphertext và tag. Phạm vi bài làm là SP 800-38A đến F và RFC 8452, không bao gồm SP 800-38G.

## Task 3 — Executable, thư viện tĩnh và thư viện động

```sh
file -L build/modes/aes_tests build/modes/libaes_modes.a build/modes/libaes_modes.so
./build/consumer-static/aes_consumer
./build/consumer-shared/aes_consumer
```

Hai chương trình dùng cùng `task3/main.cpp`, nhưng liên kết lần lượt với `.a` và `.so`. Mỗi chương trình kiểm tra AES-128 với ciphertext chuẩn độc lập và in `PASS: FIPS 197 AES-128 encryption/decryption known-answer test` khi đúng.

Có thể xem phụ thuộc thư viện động bằng:

```sh
ldd build/consumer-static/aes_consumer
ldd build/consumer-shared/aes_consumer
```

Bản shared phải nạp `libaes_modes.so`; bản static không phụ thuộc động vào thư viện AES này, nhưng vẫn có thể dùng thư viện hệ thống động như `libstdc++`.

Trên Linux, executable là ELF, thư viện tĩnh là `.a`, thư viện động là `.so`; không phải các định dạng `.exe`, `.lib`, `.dll` của Windows. Bài đã kiểm chứng trên Linux; chưa kiểm chứng build Windows.

Nếu cần cài đặt executable, header, thư viện và CMake package:

```sh
cmake --install build --prefix "$PWD/build/install"
```

## Task 4 — Sử dụng từ Python và chạy container

### 4.1. Python gọi thư viện C++

```sh
python3 -B task4/main.py build/modes/libaes_modes.so
```

`task4/aes_modes.py` nạp đúng đường dẫn thư viện động được truyền vào, gọi các hàm trong `modes/include/aes_c.h` qua `ctypes`. Thuật toán vẫn chạy trong C++, không có bản mã hóa Python thay thế.

Chương trình kiểm tra known-answer vectors, dữ liệu nhị phân và từ chối tag giả; thành công kết thúc bằng `All native Python demo checks passed.`

### 4.2. Container

```sh
podman build -t aes-lab .
podman run --rm aes-lab
```

Container mặc định chạy chương trình Task 2. Để chạy Task 1 hoặc phần Python bên trong cùng image:

```sh
podman run --rm aes-lab /opt/aes/bin/AES
podman run --rm aes-lab python3 /opt/aes/share/AESModes/python/main.py /opt/aes/lib/libaes_modes.so
```

`Dockerfile` dùng multi-stage build; image chạy chỉ chứa chương trình đã cài đặt cùng runtime, không chứa compiler hay source build. Các lệnh container đã kiểm chứng bằng Podman; nếu dùng Docker, thay `podman` bằng `docker`.

## Phạm vi và lưu ý

- AES xử lý khối 16 byte; các mode xử lý thông điệp theo API trong từng header.
- GCM hiện dùng nonce 12 byte, tag 16 byte. CCM và GCM-SIV trả về `ciphertext || tag`; GCM cũng dùng định dạng này.
- Caller cung cấp IV, nonce, counter hoặc tweak; thư viện không tự sinh hay gắn chúng vào ciphertext.
- Các khóa/IV/nonce cố định trong chương trình kiểm tra là dữ liệu test công khai, không dùng cho dữ liệu thật. Không tái sử dụng nonce GCM/CCM hoặc chuỗi counter CTR dưới cùng khóa.
- Đây là bài thực hành, không phải thư viện được chứng nhận FIPS hay đã qua đánh giá bảo mật để dùng trong sản phẩm.
