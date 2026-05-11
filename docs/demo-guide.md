# 🎓 Hướng dẫn Thuyết trình Demo Dành cho Giảng Viên

Tài liệu này hướng dẫn cách chạy Demo để phô diễn 100% các tính năng từ FR1 đến FR8 giúp ăn trọn điểm dự án.

## Demo 1: Password Analysis & Registration (FR1 & FR2)
1. Bật giao diện `/register`. Gõ mật khẩu `123456`.
2. Trỏ chuột cho Giảng viên thấy **Zxcvbn Score** nhấp nháy đỏ báo cực yếu.
3. Gõ `qwerty1234`. Nhấn Submit. Hệ thống văng Alert báo FR2 Policy Alert (lỗi Sequence Pattern qwerty & Thiếu Ký tự đặc biệt).
4. Click ngay nút `⚡ Tạo mật khẩu mạnh tự động` (Đây là **FR7 Generator** hoạt động sinh pass 20 chars random).
5. Đăng ký thành công.
> **Key talk point:** Nhấn mạnh hệ thống áp dụng tiêu chuẩn FR2 cấm sequence pattern và FR7 Bitwarden generator.

## Demo 2: Đổi mật khẩu & FR4 Reuse Detection (FR3 & FR4)
1. Trong Dashboard bên tab `Hồ sơ & Mật khẩu`, gõ mật khẩu mới *trùng với cái vừa đăng ký ở phần 1*.
2. Nhấn cập nhật. Hệ thống báo đỏ rực: *"Không được dùng lại 5 mật khẩu chuẩn gần nhất"*.
3. Thử dùng 1 mật khẩu quá yếu kiểu `abc12`. Hệ thống dội lại bằng zxcvbn score.
> **Key talk point:** Explain với Giảng viên việc DB hoàn toàn dùng Bcrypt (*FR3*) và không ai thấy mật khẩu cũ do `password_history` lưu băm so sánh.

## Demo 3: Brute Force Kicker (FR5)
1. Logout.
2. Thử điền bừa Account Admin với mật khẩu bậy.
3. Gõ sai lần 1-4. Hệ thống nhắc nhở Countdown attempts còn lại.
4. Gõ sai cái thứ 5. BOOM. Bảng đỏ báo `LOCKED ACCOUNT 15 minutes` hiện ra.
5. F5 trang và cố login từ Request khác -> Hệ thống API trực tiếp chặn "Account Closed".
> **Key talk point:** "Project em có Network Rate Limit (10 tries/ip) VÀ DB Account Lockout (Lớp 2). Rất hiếm dự án sinh viên triển khai 2-tier defense."

## Demo 4: Quyền Lực TOTP 2FA (FR6)
1. Login vào Acc vừa tạo (bằng pass đúng). Bấm sang tab 2FA.
2. Click `Kích hoạt 2FA`. Mã QR Code hiện ra. Mở Phone lên (Google Auth App).
3. Scan mã và điền 6 số. Bấm gửi. Hệ thống Setup thành công (Cờ `is_2fa_enabled=1`).
4. LOGOUT. Login lại. Hệ thống hiện bảng OTP. Cố gắng xóa Console sửa JS bypass cũng vô dụng do chưa có JWT xịn.
5. Gõ OTP vào là Load Dashboard.

## Demo 5: Bắt bài Hành động với Audit Logs (FR8)
1. Giải thích FR8: "Mọi thao tác chúng ta vừa làm từ nãy đến giờ đều đã có vết IP."
2. Show cho giảng viên xem DB Query hoặc Data Terminal trong bảng `audit_logs`:
  - Thấy ghi được các hành động `LOGIN_SUCCESS`, `LOGIN_FAILED`, `ACCOUNT_LOCKED`, `2FA_ENABLED`.
> **Key talk point:** "Điều làm hệ thống này trở nên 'PRO' là tính Tracking và Audit. Mọi request Security đều được ghi vết giống y chang Firebase hay AWS CloudTrail. Mọi hành động Login Fail đều có logs IP đi kèm."
