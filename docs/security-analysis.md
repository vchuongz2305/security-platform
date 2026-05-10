# 🛡️ Security Analysis (OWASP Mapping)

Báo cáo vùi phân tích tính năng bảo mật căn cứ theo tiêu chuẩn Enterprise Authentication Security.

## 1. Mapping FR (Functional Requirements) to OWASP Top 10

| OWASP Vulnerability | Cách Project Phòng Chống & Mitigate | Module liên quan |
|---|---|---|
| **A01: Broken Access Control** | Authentication Check Middleware cho mọi API. JWT xác thực. Stateless Token. | `requireAuth` Middleware |
| **A02: Cryptographic Failures** | Không lưu plain-text, băm bằng Bcrypt12-salt ngẫu nhiên (FR3). | `hash.js` |
| **A03: SQL Injection** | Sử dụng Sqlite Parameterized query chống tẩu thoát. | `userModel.js` |
| **A07: Identification Failures** | Lớp 1 chặn Credential Stuffing (FR5 Rate Limit), chống reuse password (FR4), Lớp 2 khóa Acc (FR5), Zxcvbn chống password pattern yếu (FR2). | `authController` |
| **A09: Security Logging** | Audit log tracking IP và hành động Account thay đổi, ghi Logs (FR8). | `userModel / audit_logs` |

## 2. Điểm mạnh và cơ chế đặc biệt (Core Defensive Strategy)

### Defensive 2FA Flow
Thiết kế của Endpoint Xác nhận Đăng nhập 2 Bước tuân thủ chuẩn Enterprise:
- Giảm thiểu rủi ro sinh JWT bypass. Trả `PendingToken` 5 phút thay vì JWT Auth, Token này chỉ có 2 scopes: id, email (Không có scope Admin hay dashboard_access).

### Anti-Bruteforce & Stuffing 
Dự án được bảo vệ **2-Tiers (2 vòng):**
- Ngay khi attacker dò quét tự động (Network DDos/Stuffing), IP của hắn bị thư viện `rate-limit` cấm đứng hình ngay vì gọi Endpoint `/login` >10 lần / phút. Database không hề sứt mẻ IO.
- Nếu attacker dùng IP Xoay (Botnet Proxy) để BruteForce vào 1 Acc VIP đích danh: Lớp số 2 Application sẽ can thiệp. Counter báo đếm sai `= 5`. Set Timestamp DB block ngay 15 phút. Toàn bộ 99% requests còn lại bị API ném lỗi `429 Account Locked` thay vì tốn CPU hashing bcrypt tiếp tục.

### History Reuse Detection
Dự án không có tính năng cấm trùng password rởm chỉ với Array Memory. Table Database `password_history` được lập. Cứỗi mỗi lần đổi mật khẩu, server phải Bcrypt-Compare với tận 5 Hash quá khứ. Điều này giúp ngăn chặn triệt để hành động người dùng đảo pass, gia tăng Security Identity Lifecycle đáng kể.

### 🧠 Password Intelligence System (Bitwarden Inspired)
Nâng cấp trí tuệ bảo mật cho người dùng:
- **Entropy Calculation**: Không chỉ dựa trên pattern, hệ thống tính toán Entropy (bits) dựa trên lý thuyết thông tin. Giúp đánh giá khách quan độ phức tạp thực sự của mật khẩu.
- **Leak Simulation DB**: Tích hợp danh sách đen (Blacklist) mô phỏng các Database bị rò rỉ (Pwned). Cảnh báo ngay lập tức nếu người dùng sử dụng mật khẩu nằm trong danh sách rủi ro bị hacker nhắm tới.
- **Dynamic Risk Assessment**: Kết hợp Entropy, zxcvbn score và Leak status để gán nhãn rủi ro (Low / Medium / High / Critical), giúp người dùng dễ dàng nhận diện mức độ an toàn của tài khoản.
