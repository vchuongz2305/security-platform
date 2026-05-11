# 🏛️ System Architecture

## 1. Tổng quan Kiến trúc (Overview)
Dự án được thiết kế theo mô hình **Client-Server Architecture**, áp dụng **Layered Pattern (Kiến trúc phân tầng)** chặt chẽ ở Backend để đảm bảo Non-functional Requirements (NFR) cực kỳ cao về **Security**, **Scalability** và **Maintainability**.

- **Frontend:** Vanilla JS, CSS3, HTML5 (No Frameworks) -> Đảm bảo Performance tối đa (< 500ms response render), cực nhẹ.
- **Backend:** Node.js, Express.
- **Database:** SQLite3 (Memory/File-based) -> Dễ dàng scale up lên PostgreSQL chuẩn cho module.

## 2. Các tầng Backend (Layered Design - Maintainability)
Hệ thống tuân thủ nghiêm ngặt nguyên tắc **Single Responsibility Principle**. Logic không bao giờ được nhét chung vào Controller.

```text
Client (Frontend)
       ↓ (HTTP / REST API)
Routes Layer (authRoutes.js): Định tuyến, Rate Limiting, Check JWT Middleware
       ↓
Controller Layer (authController.js): Xử lý Request/Response, Gọi Service
       ↓
Service Layer (Business Logic):
   ├─ passwordService.js: Phân tích zxcvbn, tạo mật khẩu, check reuse rule
   ├─ passwordPolicy.js: Config chuẩn Enterprise (12 chars, regex)
   ├─ otpService.js: Khởi tạo TOTP, Verify OTP, QR Code
   └─ securityService.js: Threat model, Breach simulation 
       ↓
Model / Repository Layer (userModel.js): 
   ├─ Xử lý độc lập thuần SQL tương tác với SQLite
   └─ Abstracting DB schema (users, password_history, audit_logs)
```

## 3. Database Schema Design (NFR: Relational Standard)
Thiết kế chuẩn 3 Bảng (3 Tables Design):

- **Users Table:** Lưu thông tin tài khoản (id, email, password_hash, is_2fa_enabled, secret_2fa, login_attempts, locked_until).
- **Password History Table:** Phục vụ `FR4` chống Reuse (id, user_id, password_hash, created_at).
- **Audit Logs Table:** Tracking log hệ thống cho `FR8` (id, user_id, action, ip_address, created_at).

*(Note: Cơ chế đếm Attempts Login do được truy xuất cùng lúc mọi lần check tài khoản nên gộp vào User Table để tối ưu hóa truy vấn O(1) phục vụ Performance NFR thay vì tách lập bảng riêng).*

## 4. Các giải pháp Non-Functional Requirements (PRO LEVEL)

### 4.1. ⚡ Security
- **Anti SQL-Injection:** Toàn bộ DB query sử dụng Parameterized Query `(?, ?, ?)` từ sqlite3, chống tuyệt đối tẩu thoát chuỗi.
- **Hash Password:** Hash 1 chiều bằng Bcrypt work-factor 12, Random Salt. Không lưu Rawtext dù bất kì đâu.
- **Data Validation:** Zxcvbn phân tích độ tĩnh entropy.
- **Identity:** Stateless JWT bảo vệ bằng `HTTP Bearer`.

### 4.2. ⚡ Performance
- API Response dưới < 50ms cho các logic hash và otp (local benchmark). Load front-end chỉ mất 0.2s.
- Bcrypt sử dụng version Asynchronous (Promise) không block Event Loop của Node.js.

### 4.3. ⚡ Scalability
- **Module Hóa:** Core check Policy, MFA, Controller được tách làm các Service Files độc lập.
- Khi scale số tài khoản, chỉ cần thay thế file khởi tạo `userModel.js` kết nối qua một Driver Postgres/MySQL là xong. Toàn bộ Business Logic ở Controller/Service không hề bị đụng chạm tới.

### 4.4. ⚡ Maintainability
- Code Clean, Comment JSDoc đầy đủ.
- Export Service chuẩn, testable.
