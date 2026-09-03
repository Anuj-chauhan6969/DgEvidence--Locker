"""
email_util.py – Email sending utilities for DgEvidenceLocker
Uses the Gmail account from otpnew.py
"""
import os
import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SENDER_EMAIL = os.environ.get('SENDER_EMAIL', '')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD', '')
SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))


def _send_email(to_email: str, subject: str, html_body: str) -> bool:
    """Internal helper to send an HTML email."""
    try:
        if not SENDER_EMAIL or not SENDER_PASSWORD:
            print('[email_util] SMTP credentials are not configured.')
            return False
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f'DgEvidenceLocker <{SENDER_EMAIL}>'
        msg['To'] = to_email
        msg.attach(MIMEText(html_body, 'html'))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f'[email_util] Failed to send email to {to_email}: {e}')
        return False


def generate_otp() -> str:
    """Generate a 6-digit OTP string."""
    return str(random.randint(100000, 999999))


def send_otp(to_email: str, otp: str, purpose: str = 'login') -> bool:
    """Send a 6-digit OTP for login 2FA or registration verification."""
    purpose_label = 'Login Verification' if purpose == 'login' else 'Email Verification'
    subject = f'🔐 Your DgEvidenceLocker OTP – {otp}'
    html = f"""
    <div style="font-family:Inter,sans-serif;max-width:480px;margin:auto;background:#0f172a;
                padding:32px;border-radius:16px;color:#f1f5f9;">
      <h2 style="color:#f97316;margin-bottom:8px;">🔐 Digital Evidence Locker</h2>
      <h3 style="color:#e2e8f0;margin-bottom:24px;">{purpose_label}</h3>
      <p style="color:#94a3b8;">Your one-time password is:</p>
      <div style="background:#1e293b;border:2px solid #f97316;border-radius:12px;
                  padding:24px;text-align:center;margin:20px 0;">
        <span style="font-size:42px;font-weight:700;letter-spacing:12px;color:#f97316;">{otp}</span>
      </div>
      <p style="color:#94a3b8;font-size:14px;">This OTP expires in <strong style="color:#f1f5f9;">5 minutes</strong>.</p>
      <p style="color:#94a3b8;font-size:14px;">If you did not request this, please ignore this email.</p>
      <hr style="border-color:#334155;margin:24px 0;">
      <p style="color:#475569;font-size:12px;">DgEvidenceLocker — Secure Digital Evidence Management</p>
    </div>
    """
    return _send_email(to_email, subject, html)


def send_upload_notification(to_email: str, username: str, evidence_id: str, filename: str) -> bool:
    """Notify user after successful evidence upload."""
    subject = f'✅ Evidence Uploaded – {evidence_id}'
    html = f"""
    <div style="font-family:Inter,sans-serif;max-width:480px;margin:auto;background:#0f172a;
                padding:32px;border-radius:16px;color:#f1f5f9;">
      <h2 style="color:#22c55e;">✅ Evidence Upload Successful</h2>
      <p>Hi <strong>{username}</strong>,</p>
      <p>Your evidence has been securely uploaded and encrypted.</p>
      <table style="width:100%;background:#1e293b;border-radius:8px;padding:16px;border-collapse:collapse;">
        <tr><td style="color:#94a3b8;padding:6px 0;">Evidence ID</td>
            <td style="color:#f97316;font-family:monospace;">{evidence_id}</td></tr>
        <tr><td style="color:#94a3b8;padding:6px 0;">File</td>
            <td style="color:#f1f5f9;">{filename}</td></tr>
        <tr><td style="color:#94a3b8;padding:6px 0;">Status</td>
            <td style="color:#22c55e;">🔒 Encrypted &amp; Stored</td></tr>
      </table>
      <p style="color:#94a3b8;font-size:13px;margin-top:16px;">
        Your evidence is now immutable and tamper-proof. A SHA-256 hash has been recorded.
      </p>
      <hr style="border-color:#334155;margin:24px 0;">
      <p style="color:#475569;font-size:12px;">DgEvidenceLocker — Secure Digital Evidence Management</p>
    </div>
    """
    return _send_email(to_email, subject, html)


def send_status_notification(to_email: str, username: str, evidence_id: str, new_status: str) -> bool:
    """Notify user when their evidence status changes."""
    status_colors = {'verified': '#22c55e', 'rejected': '#ef4444', 'pending': '#f97316', 'archived': '#94a3b8'}
    color = status_colors.get(new_status.lower(), '#94a3b8')
    subject = f'📋 Evidence {evidence_id} – Status: {new_status.title()}'
    html = f"""
    <div style="font-family:Inter,sans-serif;max-width:480px;margin:auto;background:#0f172a;
                padding:32px;border-radius:16px;color:#f1f5f9;">
      <h2 style="color:{color};">📋 Evidence Status Updated</h2>
      <p>Hi <strong>{username}</strong>,</p>
      <p>The status of your evidence has been updated by an administrator.</p>
      <table style="width:100%;background:#1e293b;border-radius:8px;padding:16px;border-collapse:collapse;">
        <tr><td style="color:#94a3b8;padding:6px 0;">Evidence ID</td>
            <td style="color:#f97316;font-family:monospace;">{evidence_id}</td></tr>
        <tr><td style="color:#94a3b8;padding:6px 0;">New Status</td>
            <td style="color:{color};font-weight:700;">{new_status.upper()}</td></tr>
      </table>
      <hr style="border-color:#334155;margin:24px 0;">
      <p style="color:#475569;font-size:12px;">DgEvidenceLocker — Secure Digital Evidence Management</p>
    </div>
    """
    return _send_email(to_email, subject, html)


def send_delete_request_admin_notification(admin_email: str, username: str, evidence_id: str, reason: str) -> bool:
    """Notify admin of a new delete request."""
    subject = f'🗑️ Delete Request – {evidence_id} from {username}'
    html = f"""
    <div style="font-family:Inter,sans-serif;max-width:480px;margin:auto;background:#0f172a;
                padding:32px;border-radius:16px;color:#f1f5f9;">
      <h2 style="color:#ef4444;">🗑️ Delete Request Submitted</h2>
      <p>A user has submitted a delete request for evidence.</p>
      <table style="width:100%;background:#1e293b;border-radius:8px;padding:16px;border-collapse:collapse;">
        <tr><td style="color:#94a3b8;padding:6px 0;">User</td>
            <td style="color:#f1f5f9;">{username}</td></tr>
        <tr><td style="color:#94a3b8;padding:6px 0;">Evidence ID</td>
            <td style="color:#f97316;font-family:monospace;">{evidence_id}</td></tr>
        <tr><td style="color:#94a3b8;padding:6px 0;">Reason</td>
            <td style="color:#f1f5f9;">{reason}</td></tr>
      </table>
      <p style="color:#94a3b8;font-size:13px;margin-top:16px;">
        Please log in to the Admin Dashboard to review and approve or reject this request.
      </p>
      <hr style="border-color:#334155;margin:24px 0;">
      <p style="color:#475569;font-size:12px;">DgEvidenceLocker — Admin Notification</p>
    </div>
    """
    return _send_email(admin_email, subject, html)


def send_delete_request_status(to_email: str, username: str, evidence_id: str, approved: bool) -> bool:
    """Notify user of delete request outcome."""
    status = 'Approved' if approved else 'Rejected'
    color = '#22c55e' if approved else '#ef4444'
    subject = f'🗑️ Delete Request {status} – {evidence_id}'
    html = f"""
    <div style="font-family:Inter,sans-serif;max-width:480px;margin:auto;background:#0f172a;
                padding:32px;border-radius:16px;color:#f1f5f9;">
      <h2 style="color:{color};">🗑️ Delete Request {status}</h2>
      <p>Hi <strong>{username}</strong>,</p>
      <p>Your delete request for evidence <span style="color:#f97316;font-family:monospace;">{evidence_id}</span>
         has been <strong style="color:{color};">{status.lower()}</strong> by an administrator.</p>
      <hr style="border-color:#334155;margin:24px 0;">
      <p style="color:#475569;font-size:12px;">DgEvidenceLocker — Secure Digital Evidence Management</p>
    </div>
    """
    return _send_email(to_email, subject, html)


def send_delete_confirmation_otp(to_email: str, username: str, evidence_id: str, otp: str) -> bool:
    """Send OTP to user for delete confirmation."""
    subject = f'🔐 Delete Confirmation OTP – {evidence_id}'
    html = f"""
    <div style="font-family:Inter,sans-serif;max-width:480px;margin:auto;background:#0f172a;
                padding:32px;border-radius:16px;color:#f1f5f9;">
      <h2 style="color:#f97316;">🔐 Delete Confirmation Required</h2>
      <p>Hi <strong>{username}</strong>,</p>
      <p>An administrator has approved your delete request for evidence:</p>
      <table style="width:100%;background:#1e293b;border-radius:8px;padding:16px;border-collapse:collapse;">
        <tr><td style="color:#94a3b8;padding:6px 0;">Evidence ID</td>
            <td style="color:#f97316;font-family:monospace;">{evidence_id}</td></tr>
      </table>
      <p style="color:#94a3b8;margin-top:20px;">To confirm you are the genuine owner, please use this OTP:</p>
      <div style="background:#1e293b;border:2px solid #f97316;border-radius:12px;
                  padding:24px;text-align:center;margin:20px 0;">
        <span style="font-size:42px;font-weight:700;letter-spacing:12px;color:#f97316;">{otp}</span>
      </div>
      <p style="color:#94a3b8;font-size:14px;">This OTP expires in <strong style="color:#f1f5f9;">30 days</strong>.</p>
      <p style="color:#ef4444;font-size:14px;"><strong>⚠️ Important:</strong> If you did not request this deletion, please contact support immediately.</p>
      <hr style="border-color:#334155;margin:24px 0;">
      <p style="color:#475569;font-size:12px;">DgEvidenceLocker — Secure Digital Evidence Management</p>
    </div>
    """
    return _send_email(to_email, subject, html)
