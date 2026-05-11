/**
 * emailService.js
 * Handles sending security alerts and notifications.
 */

const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST || 'smtp.ethereal.email',
  port: process.env.EMAIL_PORT || 587,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER || '',
    pass: process.env.EMAIL_PASS || '',
  },
});

const APP_NAME = 'Layer 8 Security Systems';

/**
 * Send a security alert email
 */
async function sendSecurityAlert(to, { type, details, ip, location = 'Unknown', device = 'Unknown' }) {
  // If no email configured, log to console for demo purposes
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.log('\n📧 [SECURITY ALERT EMAIL MOCK]');
    console.log(`To: ${to}`);
    console.log(`Type: ${type}`);
    console.log(`Details: ${details}`);
    console.log(`IP: ${ip} | Device: ${device}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    return true;
  }

  const subjects = {
    UNUSUAL_LOGIN: '⚠️ Cảnh báo: Phát hiện đăng nhập bất thường',
    PASSWORD_CHANGED: '🔐 Cảnh báo: Mật khẩu của bạn đã được thay đổi',
    '2FA_ENABLED': '✅ Thông báo: 2FA đã được kích hoạt',
    '2FA_DISABLED': '⚠️ Cảnh báo: 2FA đã bị vô hiệu hóa',
    ACCOUNT_LOCKED: '🚫 Cảnh báo: Tài khoản của bạn đã bị khóa tạm thời',
  };

  const subject = subjects[type] || `[${APP_NAME}] Security Notification`;

  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
      <div style="background-color: #1a1a1a; color: #ffffff; padding: 20px; text-align: center;">
        <h1 style="margin: 0; font-size: 24px;">${APP_NAME}</h1>
      </div>
      <div style="padding: 30px; line-height: 1.6; color: #333333;">
        <h2 style="color: #d32f2f; margin-top: 0;">${subject}</h2>
        <p>Xin chào,</p>
        <p>Chúng tôi phát hiện một sự kiện bảo mật quan trọng trên tài khoản của bạn:</p>
        
        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 4px; margin: 20px 0;">
          <p style="margin: 5px 0;"><strong>Sự kiện:</strong> ${details}</p>
          <p style="margin: 5px 0;"><strong>Thời gian:</strong> ${new Date().toLocaleString('vi-VN')}</p>
          <p style="margin: 5px 0;"><strong>Địa chỉ IP:</strong> ${ip}</p>
          <p style="margin: 5px 0;"><strong>Thiết bị:</strong> ${device}</p>
        </div>

        <p>Nếu đây là hành động của bạn, bạn có thể bỏ qua email này.</p>
        <p style="color: #d32f2f; font-weight: bold;">Nếu bạn KHÔNG thực hiện hành động này, vui lòng liên hệ với bộ phận hỗ trợ ngay lập tức hoặc đổi mật khẩu của bạn.</p>
        
        <div style="text-align: center; margin-top: 30px;">
          <a href="#" style="background-color: #007bff; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">Kiểm tra hoạt động</a>
        </div>
      </div>
      <div style="background-color: #f9f9f9; padding: 20px; text-align: center; font-size: 12px; color: #777777; border-top: 1px solid #eeeeee;">
        <p>© 2026 Enterprise Identity Platform. Tất cả các quyền được bảo lưu.</p>
        <p>Đây là email tự động, vui lòng không trả lời.</p>
      </div>
    </div>
  `;

  try {
    await transporter.sendMail({
      from: `"${APP_NAME}" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html,
    });
    return true;
  } catch (error) {
    console.error('Error sending security email:', error);
    return false;
  }
}

module.exports = { sendSecurityAlert };
