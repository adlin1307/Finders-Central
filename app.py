import os
import sqlite3
import logging
import secrets
import urllib.parse
import socket
import smtplib
import time
socket.setdefaulttimeout(5.0)  # Guard against slow or unreachable SMTP connections
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, abort, has_request_context, jsonify, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from dotenv import load_dotenv
import pillow_heif
pillow_heif.register_avif_opener()
from PIL import Image
import hashlib
import re
from difflib import SequenceMatcher

# Configure application logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s"
)
logger = logging.getLogger(__name__)

# Load environment variables from .env if present
load_dotenv()

app = Flask(__name__)

# --- Session Secret Configuration ---
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
secret_key = os.environ.get("FLASK_SECRET_KEY")

if not secret_key:
    if not os.path.exists(env_path):
        generated_secret = secrets.token_hex(32)
        try:
            with open(env_path, "w") as f:
                f.write(f"# Finder's Central local environment configuration\nFLASK_SECRET_KEY={generated_secret}\n")
            secret_key = generated_secret
            logger.info("Generated persistent session secret and saved to local .env file.")
        except Exception:
            secret_key = secrets.token_hex(32)
            logger.warning("Could not persist secret to .env; using ephemeral secret key.")
    else:
        secret_key = secrets.token_hex(32)
        logger.warning(
            "FLASK_SECRET_KEY is not set in existing .env file. "
            "Configure FLASK_SECRET_KEY in .env for persistent sessions across restarts."
        )

app.secret_key = secret_key

# --- Session Cookie & Upload Hardening ---
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1", "t"),
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024  # 5 MB max upload
)

# --- Mail Configuration ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER') or os.environ.get('MAIL_USERNAME') or 'finders.central@gmail.com'
app.config['MAIL_TIMEOUT'] = float(os.environ.get('MAIL_TIMEOUT', 5.0))

mail = Mail(app)

UPLOAD_FOLDER = "static/uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# --- CSRF Protection ---
def get_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.before_request
def validate_csrf():
    if request.method == "POST":
        token = request.form.get("csrf_token")
        expected = session.get("_csrf_token")
        if not expected or not token or not secrets.compare_digest(token, expected):
            logger.warning("CSRF validation failed on POST request to %s", request.path)
            if request.path == "/report":
                user = session.get("user", "Guest")
                return render_template(
                    "report.html",
                    error="Security verification failed (invalid or missing session token). Please try submitting again.",
                    form_data=request.form,
                    user=user
                ), 400
            elif request.path == "/signup":
                return render_template(
                    "signup.html",
                    error="Security verification failed (invalid or missing CSRF token). Please try again."
                ), 400
            elif request.path.startswith("/connection_request") or request.path.startswith("/guest/connection_request"):
                user = session.get("user", "Guest")
                return render_template(
                    "error.html",
                    error_title="400 — Security Verification Failed",
                    error_message="Security verification failed (invalid or missing CSRF session token). Please refresh the page and try again.",
                    user=user
                ), 400
            return render_template(
                "login.html",
                error="Security verification failed (invalid or missing CSRF token). Please try again."
            ), 400


# --- Sensitive Upload Protection ---
SENSITIVE_FILENAME_KEYWORDS = (
    "aadhar",
    "college_id",
    "passport",
    "id_card",
    "identity",
    "license",
    "pan_card",
    "voter",
)


@app.before_request
def protect_sensitive_uploads():
    raw_path = request.path
    unquoted = urllib.parse.unquote(raw_path)
    normalized = os.path.normpath(unquoted).replace("\\", "/")

    if normalized.startswith("/static/uploads/"):
        filename = normalized[len("/static/uploads/"):].strip("/")
        if not filename or ".." in filename or "/" in filename:
            abort(403)

        lower_filename = filename.lower()
        is_sensitive = False

        for kw in SENSITIVE_FILENAME_KEYWORDS:
            if kw in lower_filename:
                is_sensitive = True
                break

        if not is_sensitive:
            try:
                conn = sqlite3.connect("lostfound.db")
                c = conn.cursor()
                c.execute("SELECT category FROM reports WHERE lower(image) = ?", (lower_filename,))
                rows = c.fetchall()
                conn.close()
                for (cat,) in rows:
                    if cat and cat.strip().lower() == "id cards":
                        is_sensitive = True
                        break
            except Exception as e:
                logger.error("Error checking report category for upload: %s", type(e).__name__)

        if is_sensitive:
            current_user = session.get("user")
            claimed_reports = session.get("claimed_reports", [])
            allowed = False
            try:
                conn = sqlite3.connect("lostfound.db")
                c = conn.cursor()
                c.execute("SELECT id, owner FROM reports WHERE lower(image) = ?", (lower_filename,))
                rows = c.fetchall()
                conn.close()
                for rep_id, rep_owner in rows:
                    if current_user and current_user != "Guest" and rep_owner == current_user:
                        allowed = True
                        break
                    if rep_id in claimed_reports:
                        allowed = True
                        break
            except Exception:
                abort(403)

            if not allowed:
                abort(403)


# --- Image Structural Validation & Unique Filenames ---
def validate_uploaded_image(file_storage):
    if not file_storage or not file_storage.filename:
        return False, "", "No file selected."

    original_filename = secure_filename(file_storage.filename)
    if not original_filename or "." not in original_filename:
        return False, "", "Invalid filename."

    ext = original_filename.rsplit(".", 1)[1].lower()
    allowed_extensions = {"png", "jpg", "jpeg", "webp", "avif"}
    if ext not in allowed_extensions:
        return False, "", f"File extension .{ext} is not allowed. Supported formats: PNG, JPG, JPEG, WEBP, AVIF."

    try:
        file_storage.stream.seek(0)
        img = Image.open(file_storage.stream)
        img.verify()
        format_name = img.format.lower() if img.format else ""
        file_storage.stream.seek(0)

        if format_name not in ("jpeg", "png", "webp", "avif", "gif"):
            return False, "", "Uploaded file content is not a supported image format."
    except Exception:
        file_storage.stream.seek(0)
        return False, "", "Uploaded file is corrupted or not a valid image."

    unique_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(6)}.{ext}"
    return True, unique_filename, ""


# --- Template PII Masking Filters ---
@app.template_filter("mask_phone")
@app.template_filter("mask_phone_filter")
def mask_phone_filter(phone):
    if not phone:
        return ""
    phone = str(phone).strip()
    if len(phone) >= 4:
        return "******" + phone[-4:]
    return "******"


@app.template_filter("mask_email")
@app.template_filter("mask_email_filter")
def mask_email_filter(email):
    if not email or "@" not in email:
        return "******"
    name_part, domain = email.split("@", 1)
    if len(name_part) <= 2:
        masked_name = name_part[0] + "***"
    else:
        masked_name = name_part[0] + "***" + name_part[-1]
    return f"{masked_name}@{domain}"


@app.template_filter("reporter_label")
@app.template_filter("reporter_label_filter")
def reporter_label_filter(owner, verified=None):
    """
    Produces a safe, consistent public reporter label that conceals sensitive student
    register numbers and raw internal ownership/guest tokens.
    """
    if not owner:
        return "Campus Community Member"
    owner_str = str(owner).strip()

    # Student with institutional register number (e.g. URK25CS1004)
    if (owner_str.startswith("URK") and len(owner_str) == 11) or re.match(r"^[A-Z]{3}\d{2}[A-Z]{2}\d{4}$", owner_str, re.IGNORECASE):
        last_digits = owner_str[-4:]
        return f"Verified Student (***{last_digits})"

    # Campus Guest / Visitor
    if owner_str.lower() == "guest":
        return "Campus Visitor"
    if owner_str.lower().startswith("guest_"):
        suffix = owner_str.split("_")[-1][-4:]
        return f"Campus Visitor (Guest-{suffix})"

    # Generic fallback without exposing internal identifiers
    if len(owner_str) > 6:
        return f"Member (***{owner_str[-4:]})"
    return "Campus Community Member"


# Explicit dictionary registration to guarantee availability before any request
app.jinja_env.filters["reporter_label"] = reporter_label_filter
app.jinja_env.filters["reporter_label_filter"] = reporter_label_filter
app.jinja_env.filters["mask_phone"] = mask_phone_filter
app.jinja_env.filters["mask_phone_filter"] = mask_phone_filter
app.jinja_env.filters["mask_email"] = mask_email_filter
app.jinja_env.filters["mask_email_filter"] = mask_email_filter

# Module-level aliases
reporter_label = reporter_label_filter
mask_phone = mask_phone_filter
mask_email = mask_email_filter


# --- Email Status & Unified SMTP Diagnostics ---
_EMAIL_STATUS_CACHE = {
    "checked_at": 0,
    "status": None
}

def get_email_service_status(force_recheck=False):
    """
    Truthful, unified email status helper used consistently across all templates and routes.
    Distinguishes:
      - 'unconfigured': MAIL_USERNAME or MAIL_PASSWORD missing in config
      - 'connection_failed': Network, DNS, or socket failure reaching SMTP host
      - 'auth_failed': Host reachable, but SMTP authentication failed
      - 'active': SMTP connection, TLS handshake, and credentials verified
    Caches network probe results for 60 seconds to avoid latency on normal page requests.
    """
    global _EMAIL_STATUS_CACHE

    if app.config.get("TESTING") and app.config.get("_MOCK_EMAIL_STATUS"):
        return app.config["_MOCK_EMAIL_STATUS"]

    now = time.time()
    if not force_recheck and _EMAIL_STATUS_CACHE["status"] is not None and (now - _EMAIL_STATUS_CACHE["checked_at"] < 60):
        return _EMAIL_STATUS_CACHE["status"]

    server = app.config.get("MAIL_SERVER", "smtp.gmail.com")
    port = int(app.config.get("MAIL_PORT", 587))
    use_tls = bool(app.config.get("MAIL_USE_TLS", True))
    username = app.config.get("MAIL_USERNAME")
    password = app.config.get("MAIL_PASSWORD")
    sender = app.config.get("MAIL_DEFAULT_SENDER") or username or "finders.central@gmail.com"

    # Stage 1: Configuration check
    if not username or not password:
        status_info = {
            "status": "unconfigured",
            "label": "Email Unconfigured",
            "configured": False,
            "can_send": False,
            "message": "Automated email relay is unconfigured. In-app matching and connection workflows remain fully functional.",
            "server": server,
            "port": port,
            "use_tls": use_tls,
            "username_masked": mask_email(username) if username else None,
            "sender": sender
        }
        _EMAIL_STATUS_CACHE = {"checked_at": now, "status": status_info}
        return status_info

    # Stage 2: Probe SMTP connectivity with bounded timeout
    timeout = float(app.config.get("MAIL_TIMEOUT", 3.0))
    try:
        smtp_client = smtplib.SMTP(server, port, timeout=timeout)
        smtp_client.ehlo()
        if use_tls:
            smtp_client.starttls()
            smtp_client.ehlo()
        smtp_client.login(username, password)
        try:
            smtp_client.quit()
        except Exception:
            pass

        status_info = {
            "status": "active",
            "label": "Campus Email Service Active",
            "configured": True,
            "can_send": True,
            "message": "Automated campus email notifications are fully active.",
            "server": server,
            "port": port,
            "use_tls": use_tls,
            "username_masked": mask_email(username),
            "sender": sender
        }
    except smtplib.SMTPAuthenticationError:
        status_info = {
            "status": "auth_failed",
            "label": "Authentication Failed",
            "configured": True,
            "can_send": False,
            "message": "Campus mail relay authentication failed. In-app matching and connection workflows remain fully functional.",
            "server": server,
            "port": port,
            "use_tls": use_tls,
            "username_masked": mask_email(username),
            "sender": sender,
            "error_type": "SMTPAuthenticationError"
        }
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError, smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected) as e:
        status_info = {
            "status": "connection_failed",
            "label": "Mail Service Unavailable",
            "configured": True,
            "can_send": False,
            "message": "Campus mail relay connection is temporarily unavailable. In-app matching and connection workflows remain fully functional.",
            "server": server,
            "port": port,
            "use_tls": use_tls,
            "username_masked": mask_email(username),
            "sender": sender,
            "error_type": type(e).__name__
        }
    except Exception as e:
        status_info = {
            "status": "connection_failed",
            "label": "Mail Service Unavailable",
            "configured": True,
            "can_send": False,
            "message": "Campus mail relay encountered a connection issue. In-app matching and connection workflows remain fully functional.",
            "server": server,
            "port": port,
            "use_tls": use_tls,
            "username_masked": mask_email(username),
            "sender": sender,
            "error_type": type(e).__name__
        }

    _EMAIL_STATUS_CACHE = {"checked_at": now, "status": status_info}
    return status_info


def diagnose_smtp_pipeline(send_test=False, recipient=None):
    """
    Performs comprehensive diagnostic inspection across the entire SMTP notification pipeline:
      1. Configuration presence (server, port, TLS, username, password)
      2. DNS resolution of mail server host
      3. TCP socket connectivity to server:port
      4. STARTTLS handshake and credential authentication
      5. Optional live test email dispatch
    Never exposes plaintext passwords or app passwords.
    """
    server = app.config.get("MAIL_SERVER", "smtp.gmail.com")
    port = int(app.config.get("MAIL_PORT", 587))
    use_tls = bool(app.config.get("MAIL_USE_TLS", True))
    username = app.config.get("MAIL_USERNAME")
    password = app.config.get("MAIL_PASSWORD")
    sender = app.config.get("MAIL_DEFAULT_SENDER") or username or "finders.central@gmail.com"
    timeout = float(app.config.get("MAIL_TIMEOUT", 4.0))

    report = {
        "overall_status": "unconfigured",
        "summary": "",
        "config": {
            "server": server,
            "port": port,
            "use_tls": use_tls,
            "username_masked": mask_email(username) if username else None,
            "password_configured": bool(password),
            "password_length": len(password) if password else 0,
            "sender": sender
        },
        "dns": {
            "success": False,
            "resolved_ip": None,
            "error_type": None,
            "error": None
        },
        "connection": {
            "success": False,
            "error_type": None,
            "error": None
        },
        "auth": {
            "success": False,
            "authenticated_as": None,
            "error_type": None,
            "error": None
        },
        "delivery": None
    }

    if not username or not password:
        report["overall_status"] = "unconfigured"
        report["summary"] = "SMTP credentials (MAIL_USERNAME and/or MAIL_PASSWORD) are not set in the environment."
        return report

    # 1. DNS Resolution
    try:
        resolved_ip = socket.gethostbyname(server)
        report["dns"]["success"] = True
        report["dns"]["resolved_ip"] = resolved_ip
    except Exception as e:
        report["dns"]["error_type"] = type(e).__name__
        report["dns"]["error"] = str(e)
        report["overall_status"] = "connection_failed"
        report["summary"] = f"DNS resolution failed for SMTP host '{server}': {type(e).__name__}."
        return report

    # 2. TCP Socket Connection
    try:
        sock = socket.create_connection((server, port), timeout=timeout)
        sock.close()
        report["connection"]["success"] = True
    except Exception as e:
        report["connection"]["error_type"] = type(e).__name__
        report["connection"]["error"] = str(e)
        report["overall_status"] = "connection_failed"
        report["summary"] = f"TCP connection to {server}:{port} failed: {type(e).__name__}."
        return report

    # 3. SMTP TLS & Authentication
    try:
        client = smtplib.SMTP(server, port, timeout=timeout)
        client.ehlo()
        if use_tls:
            client.starttls()
            client.ehlo()
        client.login(username, password)
        report["auth"]["success"] = True
        report["auth"]["authenticated_as"] = mask_email(username)
        report["overall_status"] = "active"
        report["summary"] = "SMTP server reachable, TLS encryption verified, and authentication succeeded."
        try:
            client.quit()
        except Exception:
            pass
    except smtplib.SMTPAuthenticationError:
        report["auth"]["error_type"] = "SMTPAuthenticationError"
        report["auth"]["error"] = "Invalid username or application password."
        report["overall_status"] = "auth_failed"
        report["summary"] = "SMTP server is reachable, but credentials failed authentication."
        return report
    except Exception as e:
        report["auth"]["error_type"] = type(e).__name__
        report["auth"]["error"] = str(e)
        report["overall_status"] = "connection_failed"
        report["summary"] = f"SMTP handshake/auth failed: {type(e).__name__}."
        return report

    # 4. Optional live test email
    if send_test:
        test_recipient = recipient or os.environ.get("TEST_EMAIL_RECIPIENT") or sender
        sub = "Finder's Central — Live SMTP Diagnostic Verification"
        body = (
            "Hello!\n\n"
            "This is a verified live diagnostic test email dispatched from Finder's Central.\n\n"
            "All stages of the campus email pipeline (Configuration, DNS, TLS, Authentication, and Dispatch) "
            "are operating normally.\n\n"
            "✨ Finder's Central — Campus Lost & Found Hub"
        )
        sent = send_notification_email(test_recipient, sub, body)
        if sent:
            report["delivery"] = {
                "success": True,
                "message": "Live test email successfully dispatched via SMTP.",
                "recipient": mask_email(test_recipient)
            }
        else:
            report["delivery"] = {
                "success": False,
                "error_type": "DispatchFailed",
                "error": "Message dispatch was rejected or timed out by the SMTP server.",
                "recipient": mask_email(test_recipient)
            }

    return report


@app.context_processor
def inject_email_status():
    """Injects truthful email_status into all template rendering contexts."""
    return {"email_status": get_email_service_status()}


@app.errorhandler(403)
def forbidden_error(error):
    user = session.get("user", "Guest")
    return render_template(
        "error.html",
        error_title="403 — Access Restricted",
        error_message="You do not have permission to manage this item or connection request. If this is a guest report, please ensure you are using your private claim link.",
        user=user
    ), 403


@app.errorhandler(413)
def request_entity_too_large(error):
    user = session.get("user", "Guest")
    return render_template(
        "report.html",
        error="File size exceeds the 5MB limit. Please upload a smaller photo.",
        user=user
    ), 413


def send_notification_email(recipient_email, subject, body):
    """
    Safely sends an email notification.
    Ensures that mail configuration issues and network errors do NOT crash the caller.
    Logs errors without exposing credentials or recipient personal details.
    Uses bounded socket timeouts to prevent indefinite server hangs.
    """
    if not recipient_email:
        logger.info("Email notification skipped: No recipient email provided.")
        return False

    if not app.config.get("MAIL_USERNAME") or not app.config.get("MAIL_PASSWORD"):
        logger.warning(
            "Email notification skipped: MAIL_USERNAME or MAIL_PASSWORD not configured. "
            "Configure email credentials in .env to enable email notifications."
        )
        return False

    timeout = float(app.config.get("MAIL_TIMEOUT", 5.0))
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        sender = app.config.get("MAIL_DEFAULT_SENDER") or "finders.central@gmail.com"
        msg = Message(
            subject=subject,
            recipients=[recipient_email],
            sender=sender
        )
        msg.body = body
        mail.send(msg)
        logger.info("Notification email dispatched successfully to %s.", mask_email(recipient_email))
        return True
    except Exception as e:
        logger.error("Failed to dispatch email notification to %s: %s", mask_email(recipient_email), type(e).__name__)
        return False
    finally:
        socket.setdefaulttimeout(old_timeout)



def init_db():

    conn = sqlite3.connect("lostfound.db")

    cursor = conn.cursor()

    # ---------- USERS TABLE ---------- #

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            register_number TEXT UNIQUE,

            password TEXT

        )
    """)

    # ---------- REPORTS TABLE ---------- #

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            item_type TEXT,
            item_name TEXT,
            category TEXT,
            description TEXT,
            location TEXT,
            contact TEXT,
            email TEXT,
            status TEXT,
            timestamp TEXT,
            owner TEXT
        )
    """)

    # ---------- ADD EMAIL COLUMN IF OLD DB ---------- #

    try:

        cursor.execute("""
            ALTER TABLE reports
            ADD COLUMN email TEXT
        """)

    except:

        pass
    try:
     cursor.execute("""
        ALTER TABLE reports
        ADD COLUMN image TEXT
    """)
    except:
     pass

    # ---------- ADD OWNER COLUMN IF OLD DB ---------- #

    try:

        cursor.execute("""
            ALTER TABLE reports
            ADD COLUMN owner TEXT
        """)

    except:

        pass

    # ---------- ADD GUEST CLAIM & VERIFICATION COLUMNS ---------- #
    try:
        cursor.execute("ALTER TABLE reports ADD COLUMN claim_token_hash TEXT")
    except:
        pass

    try:
        cursor.execute("ALTER TABLE reports ADD COLUMN claim_token_expires_at TEXT")
    except:
        pass

    try:
        cursor.execute("ALTER TABLE reports ADD COLUMN verified INTEGER DEFAULT 0")
    except:
        pass

    # ---------- NOTIFIED MATCHES TABLE ---------- #
    cursor.execute("PRAGMA table_info(notified_matches)")
    notified_cols = [col[1] for col in cursor.fetchall()]
    if notified_cols and "recipient_email" not in notified_cols:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notified_matches_new (
                lost_report_id INTEGER,
                found_report_id INTEGER,
                recipient_email TEXT DEFAULT '',
                notified_at TEXT,
                PRIMARY KEY (lost_report_id, found_report_id, recipient_email)
            )
        """)
        cursor.execute("""
            INSERT OR IGNORE INTO notified_matches_new (lost_report_id, found_report_id, recipient_email, notified_at)
            SELECT lost_report_id, found_report_id, '', notified_at FROM notified_matches
        """)
        cursor.execute("DROP TABLE notified_matches")
        cursor.execute("ALTER TABLE notified_matches_new RENAME TO notified_matches")
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notified_matches (
                lost_report_id INTEGER,
                found_report_id INTEGER,
                recipient_email TEXT DEFAULT '',
                notified_at TEXT,
                PRIMARY KEY (lost_report_id, found_report_id, recipient_email)
            )
        """)

    # ---------- CONNECTION REQUESTS TABLE ---------- #
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS connection_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_report_id INTEGER NOT NULL,
            target_report_id INTEGER NOT NULL,
            requester_type TEXT NOT NULL,
            requester_id TEXT NOT NULL,
            recipient_type TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            message TEXT,
            response_note TEXT,
            contact_info TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (source_report_id) REFERENCES reports (id),
            FOREIGN KEY (target_report_id) REFERENCES reports (id)
        )
    """)

    # Mark existing verified student reports
    try:
        cursor.execute("""
            UPDATE reports
            SET verified = 1
            WHERE owner IS NOT NULL AND owner != 'Guest' AND owner NOT LIKE 'guest_%' AND (verified IS NULL OR verified = 0)
        """)
    except:
        pass

    conn.commit()

    conn.close()
init_db()


# ---------------- UNIFIED MULTI-ATTRIBUTE MATCHING SYSTEM ---------------- #

STOP_WORDS = {
    "a", "an", "the", "and", "or", "in", "on", "at", "to", "for", "with",
    "by", "from", "of", "my", "i", "lost", "found", "item", "please", "help"
}

COLOR_SYNONYMS = {
    "black": "black",
    "white": "white",
    "red": "red",
    "blue": "blue",
    "navy": "blue",
    "sky": "blue",
    "cyan": "blue",
    "green": "green",
    "yellow": "yellow",
    "orange": "orange",
    "purple": "purple",
    "violet": "purple",
    "pink": "pink",
    "rose": "pink",
    "brown": "brown",
    "grey": "gray",
    "gray": "gray",
    "silver": "silver",
    "gold": "gold",
    "golden": "gold",
    "beige": "beige",
    "maroon": "maroon",
    "teal": "teal",
    "turquoise": "teal"
}

BRAND_SYNONYMS = {
    "apple": "apple",
    "iphone": "apple",
    "ipad": "apple",
    "macbook": "apple",
    "airpods": "apple",
    "airpod": "apple",
    "iwatch": "apple",
    "samsung": "samsung",
    "galaxy": "samsung",
    "dell": "dell",
    "inspiron": "dell",
    "alienware": "dell",
    "xps": "dell",
    "hp": "hp",
    "pavilion": "hp",
    "envy": "hp",
    "omen": "hp",
    "lenovo": "lenovo",
    "thinkpad": "lenovo",
    "ideapad": "lenovo",
    "legion": "lenovo",
    "asus": "asus",
    "zenbook": "asus",
    "rog": "asus",
    "tuf": "asus",
    "acer": "acer",
    "predator": "acer",
    "swift": "acer",
    "sony": "sony",
    "bravia": "sony",
    "playstation": "sony",
    "ps5": "sony",
    "ps4": "sony",
    "boat": "boat",
    "rockerz": "boat",
    "airdopes": "boat",
    "noise": "noise",
    "colorfit": "noise",
    "realme": "realme",
    "redmi": "redmi",
    "xiaomi": "redmi",
    "oneplus": "oneplus",
    "google": "google",
    "pixel": "google",
    "milton": "milton",
    "thermosteel": "milton",
    "tupperware": "tupperware",
    "cello": "cello",
    "hydroflask": "hydro_flask",
    "stanley": "stanley",
    "nalgene": "nalgene",
    "nike": "nike",
    "adidas": "adidas",
    "puma": "puma",
    "wildcraft": "wildcraft",
    "fastrack": "fastrack",
    "casio": "casio",
    "gshock": "casio",
    "fossil": "fossil",
    "titan": "titan"
}

SUGGESTION_THRESHOLD = 0.48
AUTO_NOTIFY_THRESHOLD = 0.70

def extract_tokens(text):
    if not text:
        return set()
    words = re.findall(r'[a-zA-Z0-9]+', str(text).lower())
    return {w for w in words if w not in STOP_WORDS and len(w) > 1}

def extract_colors(text):
    if not text:
        return set()
    words = re.findall(r'\b[a-zA-Z]+\b', str(text).lower())
    found = set()
    for w in words:
        if w in COLOR_SYNONYMS:
            found.add(COLOR_SYNONYMS[w])
    return found

def extract_brands(text):
    if not text:
        return set()
    cleaned = str(text).lower()
    found = set()
    if "hydro flask" in cleaned or "hydroflask" in cleaned:
        found.add("hydro_flask")
    words = re.findall(r'\b[a-zA-Z0-9]+\b', cleaned)
    for w in words:
        if w in BRAND_SYNONYMS:
            found.add(BRAND_SYNONYMS[w])
    return found

def detect_attribute_contradiction(n1, d1, cat1, n2, d2, cat2):
    """
    Checks for explicit contradictions in category, color, or brand.
    Missing attributes are considered neutral and are not penalized.
    """
    c1 = (cat1 or "").strip().lower()
    c2 = (cat2 or "").strip().lower()
    if c1 and c2 and c1 != c2:
        if c1 not in c2 and c2 not in c1 and "other" not in (c1, c2):
            return True, "category_mismatch"

    text1 = f"{n1 or ''} {d1 or ''}"
    text2 = f"{n2 or ''} {d2 or ''}"

    colors1 = extract_colors(text1)
    colors2 = extract_colors(text2)
    if colors1 and colors2 and colors1.isdisjoint(colors2):
        return True, "color_contradiction"

    brands1 = extract_brands(text1)
    brands2 = extract_brands(text2)
    if brands1 and brands2 and brands1.isdisjoint(brands2):
        return True, "brand_contradiction"

    return False, None

def calculate_tfidf_cosine_similarity(text1, text2):
    """
    Computes TF-IDF vector cosine similarity between two text snippets using scikit-learn.
    Falls back gracefully to mathematical token-overlap similarity if unvectorizable.
    """
    if not text1 or not text2:
        return 0.0
    t1 = str(text1).strip().lower()
    t2 = str(text2).strip().lower()
    if not t1 or not t2:
        return 0.0
    if t1 == t2:
        return 1.0

    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
        vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
        tfidf_matrix = vectorizer.fit_transform([t1, t2])
        sim = float(cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0])
        return max(0.0, min(1.0, sim))
    except Exception as e:
        logger.debug("Sklearn TF-IDF fallback: %s", e)
        toks1 = extract_tokens(t1)
        toks2 = extract_tokens(t2)
        if not toks1 or not toks2:
            return 0.0
        return len(toks1 & toks2) / len(toks1 | toks2)


def analyze_match_breakdown(rep1_name, rep1_cat, rep1_desc, rep1_loc,
                            rep2_name, rep2_cat, rep2_desc, rep2_loc,
                            rep1_time=None, rep2_time=None):
    """
    Computes a hybrid AI (TF-IDF NLP + multi-attribute) match score and generates
    a transparent, explainable breakdown detailing matching attributes, detected
    contradictions, and actionable verification clues.
    """
    matching_attrs = []
    contradictions = []
    verification_clues = []

    # 1. Contradiction Detection
    has_conflict, reason = detect_attribute_contradiction(
        rep1_name, rep1_desc, rep1_cat,
        rep2_name, rep2_desc, rep2_cat
    )

    c1 = (rep1_cat or "").strip().lower()
    c2 = (rep2_cat or "").strip().lower()
    cat_score = 0.0
    if c1 and c2 and c1 != c2:
        if c1 not in c2 and c2 not in c1 and "other" not in (c1, c2):
            contradictions.append(f"The categories don't match ('{rep1_cat}' vs '{rep2_cat}').")
        else:
            matching_attrs.append(f"Both belong to compatible categories ({rep1_cat} and {rep2_cat}).")
            cat_score = 0.7
    elif c1 and c2 and c1 == c2:
        matching_attrs.append(f"Both are in the {rep1_cat} category.")
        cat_score = 1.0

    text1 = f"{rep1_name or ''} {rep1_desc or ''}"
    text2 = f"{rep2_name or ''} {rep2_desc or ''}"

    # Colors
    colors1 = extract_colors(text1)
    colors2 = extract_colors(text2)
    color_bonus = 0.0
    if colors1 and colors2:
        if colors1.isdisjoint(colors2):
            contradictions.append("Conflicting colors: the colours don't match, so double-check before contacting the other person.")
        else:
            shared_c = sorted(colors1 & colors2)
            matching_attrs.append(f"Both mention {', '.join(shared_c)}.")
            color_bonus = 0.08
    elif colors1 or colors2:
        known_c = ', '.join(sorted(colors1 or colors2))
        verification_clues.append(f"Check colour: one report mentioned '{known_c}'.")

    # Brands
    brands1 = extract_brands(text1)
    brands2 = extract_brands(text2)
    brand_bonus = 0.0
    if brands1 and brands2:
        if brands1.isdisjoint(brands2):
            contradictions.append("Conflicting brands: different brands were reported, so double-check before reaching out.")
        else:
            shared_b = sorted(brands1 & brands2)
            matching_attrs.append(f"Both mention {', '.join(shared_b).title()}.")
            brand_bonus = 0.10
    elif brands1 or brands2:
        known_b = ', '.join(sorted(brands1 or brands2)).title()
        verification_clues.append(f"Check brand identification: '{known_b}' was reported.")

    # 2. AI TF-IDF Cosine Semantic Text Similarity
    tfidf_sim = calculate_tfidf_cosine_similarity(text1, text2)
    if tfidf_sim >= 0.18:
        matching_attrs.append("The descriptions share similar details.")

    # 3. Direct Item Name Similarity
    n1 = (rep1_name or "").strip().lower()
    n2 = (rep2_name or "").strip().lower()
    tokens1 = extract_tokens(n1)
    tokens2 = extract_tokens(n2)
    name_score = 0.0
    if n1 == n2 and n1:
        name_score = 1.0
        matching_attrs.append(f"Both reports use the same name: '{rep1_name.title()}'.")
    elif (n1 and n1 in n2) or (n2 and n2 in n1):
        name_score = 0.85
        matching_attrs.append("Both item names are very similar.")
    else:
        seq_ratio = SequenceMatcher(None, n1, n2).ratio()
        if tokens1 and tokens2:
            jaccard = len(tokens1 & tokens2) / len(tokens1 | tokens2)
            name_score = max(seq_ratio, jaccard)
        else:
            name_score = seq_ratio
        shared_name_tokens = sorted(tokens1 & tokens2)
        if shared_name_tokens:
            matching_attrs.append(f"Both mention keywords: {', '.join(shared_name_tokens)}.")

    # 4. Location Proximity
    loc_tokens1 = extract_tokens(rep1_loc)
    loc_tokens2 = extract_tokens(rep2_loc)
    loc_score = 0.0
    if loc_tokens1 and loc_tokens2 and (loc_tokens1 & loc_tokens2):
        loc_score = 1.0
        shared_loc = sorted(loc_tokens1 & loc_tokens2)
        matching_attrs.append(f"The reported locations are nearby ({', '.join(shared_loc)}).")
    elif rep1_loc or rep2_loc:
        verification_clues.append(f"Compare reported locations: '{rep1_loc or 'Campus'}' vs '{rep2_loc or 'Campus'}'.")

    # 5. Time Proximity
    time_bonus = 0.0
    if rep1_time and rep2_time:
        try:
            t1 = datetime.fromisoformat(str(rep1_time).replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(str(rep2_time).replace("Z", "+00:00"))
            diff_days = abs((t1 - t2).total_seconds()) / 86400.0
            if diff_days <= 7:
                time_bonus = 0.05
                matching_attrs.append("Both were reported around the same time (within 7 days).")
            elif diff_days <= 30:
                time_bonus = 0.02
        except Exception:
            pass

    # 6. Description specific verification clues
    for kw in ["sticker", "scratch", "case", "cover", "card", "serial", "keychain", "model", "photo", "wallpaper"]:
        if kw in text1.lower() or kw in text2.lower():
            verification_clues.append(f"Check for distinguishing characteristic: '{kw}' mentioned in report description.")
            break
    if not verification_clues:
        verification_clues.append("Ask the owner to describe a private detail or marking that isn't shown in the public listing.")

    # 7. Hybrid score calculation
    raw_score = (tfidf_sim * 0.30) + (name_score * 0.25) + (cat_score * 0.20) + (loc_score * 0.10) + color_bonus + brand_bonus + time_bonus

    if has_conflict or len(contradictions) > 0:
        final_score = round(min(raw_score * 0.25, 0.22), 3)
    else:
        if cat_score >= 0.7 and name_score >= 0.75:
            raw_score = max(raw_score, 0.75)
        elif cat_score >= 0.7 and name_score >= 0.60:
            raw_score = max(raw_score, 0.65)
        final_score = round(min(raw_score, 1.0), 3)

    # Build natural, short explanation sentence
    matched_phrases = []
    if cat_score >= 0.7:
        matched_phrases.append("category")
    if tfidf_sim >= 0.18:
        matched_phrases.append("description")
    if loc_score >= 0.5:
        matched_phrases.append("reported location")
    if name_score >= 0.6 and "description" not in matched_phrases:
        matched_phrases.append("title")
    if color_bonus > 0:
        matched_phrases.append("colour")
    if brand_bonus > 0:
        matched_phrases.append("brand")

    if matched_phrases:
        if len(matched_phrases) == 1:
            phrase_str = matched_phrases[0]
            summary_sentence = f"This might match because the item {phrase_str} matches."
        elif len(matched_phrases) == 2:
            phrase_str = f"{matched_phrases[0]} and {matched_phrases[1]}"
            summary_sentence = f"This might match because the item {phrase_str} are similar."
        else:
            phrase_str = f"{', '.join(matched_phrases[:-1])}, and {matched_phrases[-1]}"
            summary_sentence = f"This might match because the item {phrase_str} are similar."
    else:
        summary_sentence = "This might match based on overall report details."

    # Build transparent score breakdown components
    # 1. Item description (TF-IDF similarity) - 30% weight
    if tfidf_sim >= 0.70:
        desc_sim = "Strong similarity"
    elif tfidf_sim >= 0.40:
        desc_sim = "Moderate similarity"
    elif tfidf_sim >= 0.18:
        desc_sim = "Some similarity"
    else:
        desc_sim = "Low similarity"
    desc_contrib = int(round(tfidf_sim * 30))

    # 2. Item title (Name similarity) - 25% weight
    if name_score >= 0.95:
        title_sim = "Exact match"
    elif name_score >= 0.75:
        title_sim = "Strong similarity"
    elif name_score >= 0.45:
        title_sim = "Moderate similarity"
    elif name_score > 0.0:
        title_sim = "Partial similarity"
    else:
        title_sim = "Different"
    title_contrib = int(round(name_score * 25))

    # 3. Category - 20% weight
    if cat_score == 1.0:
        cat_sim = "Matches"
    elif cat_score >= 0.7:
        cat_sim = "Compatible"
    else:
        cat_sim = "Different"
    cat_contrib = int(round(cat_score * 20))

    # 4. Location - 10% weight
    if loc_score == 1.0:
        loc_sim = "Similar"
    else:
        loc_sim = "Different / Not specified"
    loc_contrib = int(round(loc_score * 10))

    # 5. Colour (up to 8% bonus)
    if colors1 and colors2:
        if colors1.isdisjoint(colors2):
            color_sim = "Differs (Warning)"
            color_status = "conflict"
            color_contrib = "+0%"
        else:
            color_sim = "Matches"
            color_status = "match"
            color_contrib = "+8%"
    else:
        color_sim = "Not specified"
        color_status = "neutral"
        color_contrib = "+0%"

    # 6. Brand (up to 10% bonus)
    if brands1 and brands2:
        if brands1.isdisjoint(brands2):
            brand_sim = "Differs (Warning)"
            brand_status = "conflict"
            brand_contrib = "+0%"
        else:
            brand_sim = "Matches"
            brand_status = "match"
            brand_contrib = "+10%"
    else:
        brand_sim = "Not specified"
        brand_status = "neutral"
        brand_contrib = "+0%"

    # 7. Conflicting details
    if contradictions:
        conflict_sim = "Warning: conflicts detected"
        conflict_status = "conflict"
        conflict_detail = "; ".join(contradictions)
        conflict_contrib = "Score capped"
    else:
        conflict_sim = "None detected"
        conflict_status = "clean"
        conflict_detail = "None detected"
        conflict_contrib = "No penalty"

    components = [
        {
            "name": "Item description",
            "weight": "30%",
            "similarity": desc_sim,
            "measured_pct": f"{int(round(tfidf_sim * 100))}%",
            "contribution": f"+{desc_contrib}%",
            "status": "match" if tfidf_sim >= 0.4 else ("partial" if tfidf_sim >= 0.18 else "neutral")
        },
        {
            "name": "Item title",
            "weight": "25%",
            "similarity": title_sim,
            "measured_pct": f"{int(round(name_score * 100))}%",
            "contribution": f"+{title_contrib}%",
            "status": "match" if name_score >= 0.75 else ("partial" if name_score >= 0.45 else "neutral")
        },
        {
            "name": "Category",
            "weight": "20%",
            "similarity": cat_sim,
            "measured_pct": f"{int(round(cat_score * 100))}%",
            "contribution": f"+{cat_contrib}%",
            "status": "match" if cat_score >= 0.7 else ("conflict" if (c1 and c2 and cat_score == 0) else "neutral")
        },
        {
            "name": "Location",
            "weight": "10%",
            "similarity": loc_sim,
            "measured_pct": f"{int(round(loc_score * 100))}%",
            "contribution": f"+{loc_contrib}%",
            "status": "match" if loc_score == 1.0 else "neutral"
        },
        {
            "name": "Colour",
            "weight": "Up to +8% bonus",
            "similarity": color_sim,
            "measured_pct": "100%" if color_bonus > 0 else ("0%" if (colors1 and colors2 and colors1.isdisjoint(colors2)) else "N/A"),
            "contribution": color_contrib,
            "status": color_status
        },
        {
            "name": "Brand",
            "weight": "Up to +10% bonus",
            "similarity": brand_sim,
            "measured_pct": "100%" if brand_bonus > 0 else ("0%" if (brands1 and brands2 and brands1.isdisjoint(brands2)) else "N/A"),
            "contribution": brand_contrib,
            "status": brand_status
        },
        {
            "name": "Conflicting details",
            "weight": "Contradiction check",
            "similarity": conflict_sim,
            "measured_pct": "Conflicts present" if contradictions else "None",
            "contribution": conflict_contrib,
            "status": conflict_status,
            "detail": conflict_detail
        }
    ]

    score_pct_int = int(round(final_score * 100))
    breakdown = {
        "score": score_pct_int,
        "score_pct": f"{score_pct_int}%",
        "summary_sentence": summary_sentence,
        "matching_attributes": matching_attrs,
        "contradictions": contradictions,
        "components": components,
        "verification_clues": verification_clues,
        "nlp_similarity_pct": f"{int(round(tfidf_sim * 100))}%",
        "disclaimer": "This score helps identify possible matches, not proof that the item is yours. It doesn't confirm ownership."
    }
    return final_score, breakdown


def calculate_match_score(rep1_name, rep1_cat, rep1_desc, rep1_loc,
                          rep2_name, rep2_cat, rep2_desc, rep2_loc,
                          rep1_time=None, rep2_time=None):
    """
    Computes a hybrid AI + structured multi-attribute match score between 0.0 and 1.0.
    """
    score, _ = analyze_match_breakdown(
        rep1_name, rep1_cat, rep1_desc, rep1_loc,
        rep2_name, rep2_cat, rep2_desc, rep2_loc,
        rep1_time, rep2_time
    )
    return score


def find_matching_reports(new_report, db_path="lostfound.db", threshold=SUGGESTION_THRESHOLD):
    """
    Finds plausible matches across all active reports of the opposite type.
    new_report format: (id, item_type, item_name, category, description, location, ...)
    Works for all 4 combinations:
      1. Student lost + Student found
      2. Student lost + Guest found
      3. Guest lost + Student found
      4. Guest lost + Guest found
    Returns a sorted list of dicts: [{'report': row, 'score': int_pct, 'score_pct': 'X%', 'explanation': breakdown}]
    """
    new_id = new_report[0]
    new_type = new_report[1]
    new_name = new_report[2]
    new_cat = new_report[3]
    new_desc = new_report[4]
    new_loc = new_report[5]
    new_time = new_report[9] if len(new_report) > 9 else None
    new_owner = new_report[10] if len(new_report) > 10 else None
    target_type = "Found Item" if new_type == "Lost Item" else "Lost Item"

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM reports
        WHERE item_type = ? AND status = 'active' AND id != ?
    """, (target_type, new_id))
    candidates = cursor.fetchall()
    conn.close()

    matches = []
    for cand in candidates:
        # Exclude reports submitted by the exact same owner
        if new_owner and cand[10] and cand[10] == new_owner:
            continue

        cand_name = cand[2]
        cand_cat = cand[3]
        cand_desc = cand[4]
        cand_loc = cand[5]
        cand_time = cand[9] if len(cand) > 9 else None

        score, breakdown = analyze_match_breakdown(
            new_name, new_cat, new_desc, new_loc,
            cand_name, cand_cat, cand_desc, cand_loc,
            new_time, cand_time
        )

        if score >= threshold:
            matches.append({
                "report": cand,
                "score": int(round(score * 100)),
                "score_pct": f"{int(round(score * 100))}%",
                "explanation": breakdown
            })

    matches.sort(key=lambda m: m["score"], reverse=True)
    return matches


def get_personalized_matches(user, claimed_ids=None, db_path="lostfound.db", limit=10):
    """
    Generates personalized candidate match pairings comparing the current user's active reports
    against eligible, active campus reports of the opposite report type.
    - Authenticated students: sources are active reports where owner == user.
    - Campus guests: sources are active reports tracked in session claimed_ids.
    - Excludes self-matches, reports with the same owner, resolved/returned reports, duplicate pairs,
      and contradictory candidates (suppressed by scoring).
    - Ranks candidate matches using hybrid TF-IDF NLP semantic similarity + multi-attribute scoring.
    """
    is_student = bool(user and user != "Guest")
    claimed_ids = list(claimed_ids or [])

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    user_reports = []
    if is_student:
        cursor.execute("""
            SELECT * FROM reports
            WHERE owner = ? AND status = 'active'
            ORDER BY id DESC
        """, (user,))
        user_reports = cursor.fetchall()
    elif claimed_ids:
        placeholders = ",".join("?" for _ in claimed_ids)
        cursor.execute(f"""
            SELECT * FROM reports
            WHERE id IN ({placeholders}) AND status = 'active'
            ORDER BY id DESC
        """, claimed_ids)
        user_reports = cursor.fetchall()

    if not user_reports:
        conn.close()
        return []

    cursor.execute("SELECT * FROM reports WHERE status = 'active' ORDER BY id DESC")
    all_active = cursor.fetchall()
    conn.close()

    personalized = []
    seen_pairs = set()

    for my_rep in user_reports:
        my_id = my_rep[0]
        my_type = my_rep[1]
        my_name = my_rep[2]
        my_cat = my_rep[3]
        my_desc = my_rep[4]
        my_loc = my_rep[5]
        my_time = my_rep[9] if len(my_rep) > 9 else None
        my_owner = my_rep[10] if len(my_rep) > 10 else ""
        opp_type = "Found Item" if my_type == "Lost Item" else "Lost Item"

        for cand in all_active:
            cand_id = cand[0]
            cand_type = cand[1]
            cand_owner = cand[10] if len(cand) > 10 else ""

            # Must be opposite report type
            if cand_type != opp_type:
                continue

            # Must not be the same report
            if cand_id == my_id:
                continue

            # Must not belong to the same owner
            if is_student:
                if cand_owner == user:
                    continue
            else:
                if cand_id in claimed_ids or (cand_owner and cand_owner == my_owner):
                    continue

            # Prevent duplicate pairs
            pair_key = (my_id, cand_id)
            if pair_key in seen_pairs:
                continue

            score, breakdown = analyze_match_breakdown(
                my_name, my_cat, my_desc, my_loc,
                cand[2], cand[3], cand[4], cand[5],
                my_time, cand[9] if len(cand) > 9 else None
            )

            # Suppress matches below threshold or contradictory matches
            if score < SUGGESTION_THRESHOLD:
                continue

            seen_pairs.add(pair_key)
            personalized.append({
                "user_report": my_rep,
                "candidate_report": cand,
                "user_id": my_id,
                "candidate_id": cand_id,
                "user_item_title": my_name.title(),
                "user_item_type": my_type,
                "candidate_item_title": cand[2].title(),
                "candidate_item_type": cand_type,
                "score": int(round(score * 100)),
                "score_pct": f"{int(round(score * 100))}%",
                "explanation": breakdown,
                # Backwards compatibility
                "lost": my_rep if my_type == "Lost Item" else cand,
                "found": cand if my_type == "Lost Item" else my_rep
            })

    personalized.sort(key=lambda m: m["score"], reverse=True)
    return personalized[:limit]


def get_suggested_matches(db_path="lostfound.db", limit=6):
    """
    Generates high-confidence candidate match pairings between active lost and found reports.
    Maintained for discovery and test compatibility.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reports WHERE item_type = 'Lost Item' AND status = 'active' ORDER BY id DESC")
    lost_items = cursor.fetchall()
    cursor.execute("SELECT * FROM reports WHERE item_type = 'Found Item' AND status = 'active' ORDER BY id DESC")
    found_items = cursor.fetchall()
    conn.close()

    suggested = []
    seen_pairs = set()
    for l in lost_items:
        for f in found_items:
            pair_key = (l[0], f[0])
            if pair_key in seen_pairs:
                continue
            if l[10] and f[10] and l[10] == f[10]:
                continue
            score, breakdown = analyze_match_breakdown(
                l[2], l[3], l[4], l[5],
                f[2], f[3], f[4], f[5],
                l[9], f[9]
            )
            if score >= SUGGESTION_THRESHOLD:
                seen_pairs.add(pair_key)
                suggested.append({
                    "lost": l,
                    "found": f,
                    "score": int(round(score * 100)),
                    "score_pct": f"{int(round(score * 100))}%",
                    "explanation": breakdown
                })
    suggested.sort(key=lambda s: s["score"], reverse=True)
    return suggested[:limit]


@app.context_processor
def inject_nav_matches_count():
    """Injects matches_count for the current user into all template rendering contexts."""
    user = session.get("user")
    if not user:
        return {"matches_count": 0}
    claimed_ids = session.get("claimed_reports", [])
    if user == "Guest" and not claimed_ids:
        return {"matches_count": 0}
    try:
        matches = get_personalized_matches(user, claimed_ids=claimed_ids, db_path="lostfound.db", limit=50)
        return {"matches_count": len(matches)}
    except Exception:
        return {"matches_count": 0}


@app.route("/api/match_explanation")
def api_match_explanation():
    """
    Explainable Match Assistant API endpoint:
    Provides transparent AI reasoning and verification clues for a personalized match pair.
    Enforces authorization: the requesting user must own or have claimed at least one of the reports.
    """
    rep1_id = request.args.get("rep1_id", type=int) or request.args.get("rep1", type=int)
    rep2_id = request.args.get("rep2_id", type=int) or request.args.get("rep2", type=int)
    claim_token = request.args.get("claim_token", "").strip()

    if not rep1_id or not rep2_id:
        return jsonify({"error": "Missing report IDs"}), 400

    conn = sqlite3.connect("lostfound.db")
    c = conn.cursor()
    c.execute("SELECT * FROM reports WHERE id = ?", (rep1_id,))
    r1 = c.fetchone()
    c.execute("SELECT * FROM reports WHERE id = ?", (rep2_id,))
    r2 = c.fetchone()
    conn.close()

    if not r1 or not r2:
        return jsonify({"error": "One or both reports could not be found."}), 404

    # Ensure pairing is between opposite types (Lost Item vs Found Item)
    if r1[1] == r2[1]:
        return jsonify({"error": "Invalid report pairing: match explanations require one Lost item and one Found item."}), 400

    # Authorization Check: current user must own or have claimed at least one of the reports
    user = session.get("user")
    is_student = bool(user and user != "Guest")
    claimed_ids = session.get("claimed_reports", [])

    is_authorized = False
    if is_student:
        if (r1[10] and r1[10] == user) or (r2[10] and r2[10] == user):
            is_authorized = True
    else:
        if (r1[0] in claimed_ids) or (r2[0] in claimed_ids):
            is_authorized = True
        elif claim_token:
            if "/guest/claim/" in claim_token:
                claim_token = claim_token.split("/guest/claim/")[-1].split("?")[0].split("#")[0].strip()
            elif "/guest/manage/" in claim_token:
                claim_token = claim_token.split("/guest/manage/")[-1].split("?")[0].split("#")[0].strip()
            token_hash = hashlib.sha256(claim_token.encode('utf-8')).hexdigest()
            if (len(r1) > 12 and r1[12] == token_hash) or (len(r2) > 12 and r2[12] == token_hash):
                is_authorized = True

    if not is_authorized:
        return jsonify({
            "error": "Unauthorized: You may only view match explanations and verification clues for reports you have submitted or claimed."
        }), 403

    score, breakdown = analyze_match_breakdown(
        r1[2], r1[3], r1[4], r1[5],
        r2[2], r2[3], r2[4], r2[5],
        r1[9], r2[9]
    )
    return jsonify(breakdown)

def notify_matches(new_report, matches, db_path="lostfound.db"):
    """
    Dispatches notifications to matched parties without leaking private contact information.
    Avoids duplicate notifications using the notified_matches table.
    Enforces all requirements:
      - Symmetrical, role-appropriate copy:
        * Lost owner gets: 👀 Wait… someone found something like yours!
        * Found owner gets: 🔎 Someone might be looking for what you found!
      - Dispatches only when:
        * One report is 'Lost Item' and the other is 'Found Item'.
        * Both reports belong to different users/owners.
        * Both reports are active/unresolved.
        * Match confidence score >= 70% (AUTO_NOTIFY_THRESHOLD).
        * Exact match pair has not already been notified in notified_matches.
      - Preserves report integrity and never rolls back reports if email fails.
    """
    if not new_report or not matches:
        return

    new_id = new_report[0]
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Fetch canonical new report details from database
    cursor.execute("""
        SELECT item_type, item_name, category, description, location, contact, email, status, owner
        FROM reports WHERE id = ?
    """, (new_id,))
    new_row = cursor.fetchone()
    if not new_row:
        conn.close()
        return

    new_type, new_name, new_cat, new_desc, new_loc, new_contact, new_email, new_status, new_owner = new_row
    new_type = str(new_type or "").strip()
    new_name = str(new_name or "").strip()
    new_cat = str(new_cat or "").strip()
    new_loc = str(new_loc or "").strip()
    new_email = str(new_email or "").strip()
    new_status = str(new_status or "active").strip()
    new_owner = str(new_owner or "").strip()

    # Both reports must be active
    if new_status.lower() != "active":
        logger.info("Match notification skipped: New report #%s is not active (status=%s).", new_id, new_status)
        conn.close()
        return

    threshold_pct = int(AUTO_NOTIFY_THRESHOLD * 100)

    def is_valid_email_str(addr):
        return bool(addr and re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", str(addr).strip()))

    for m in matches:
        score_val = m.get("score", 0)
        # Credible match check (>= 70%)
        if score_val < threshold_pct:
            continue

        cand_raw = m["report"]
        cand_id = cand_raw[0]

        # Fetch canonical candidate details from database
        cursor.execute("""
            SELECT item_type, item_name, category, description, location, contact, email, status, owner
            FROM reports WHERE id = ?
        """, (cand_id,))
        cand_row = cursor.fetchone()
        if not cand_row:
            continue

        cand_type, cand_name, cand_cat, cand_desc, cand_loc, cand_contact, cand_email, cand_status, cand_owner = cand_row
        cand_type = str(cand_type or "").strip()
        cand_name = str(cand_name or "").strip()
        cand_cat = str(cand_cat or "").strip()
        cand_loc = str(cand_loc or "").strip()
        cand_email = str(cand_email or "").strip()
        cand_status = str(cand_status or "active").strip()
        cand_owner = str(cand_owner or "").strip()
        score_pct = m.get("score_pct", f"{score_val}%")

        # 1. Require one Lost Item and one Found Item
        if new_type.lower() == cand_type.lower():
            continue
        if set([new_type.lower(), cand_type.lower()]) != {"lost item", "found item"}:
            continue

        # 2. Exclude self-matches and reports owned by the exact same owner
        if new_id == cand_id:
            continue
        if new_owner and cand_owner and new_owner == cand_owner:
            continue

        # 3. Candidate report must also be active
        if cand_status.lower() != "active":
            continue

        # Canonical pair identification
        if new_type.lower() == "lost item":
            lost_id, lost_name, lost_cat, lost_loc, lost_email = (
                new_id, new_name, new_cat, new_loc, new_email
            )
            found_id, found_name, found_cat, found_loc, found_email = (
                cand_id, cand_name, cand_cat, cand_loc, cand_email
            )
        else:
            lost_id, lost_name, lost_cat, lost_loc, lost_email = (
                cand_id, cand_name, cand_cat, cand_loc, cand_email
            )
            found_id, found_name, found_cat, found_loc, found_email = (
                new_id, new_name, new_cat, new_loc, new_email
            )

        # Build safe public viewing URLs (without leaking any guest private claim tokens)
        if has_request_context():
            lost_view_url = url_for("reports", _external=True) + f"?highlight={found_id}#report-{found_id}"
            found_view_url = url_for("reports", _external=True) + f"?highlight={lost_id}#report-{lost_id}"
        else:
            lost_view_url = f"/reports?highlight={found_id}#report-{found_id}"
            found_view_url = f"/reports?highlight={lost_id}#report-{lost_id}"

        # A. NOTIFY LOST ITEM OWNER
        if is_valid_email_str(lost_email):
            cursor.execute("""
                SELECT 1 FROM notified_matches
                WHERE lost_report_id = ? AND found_report_id = ?
                  AND (recipient_email = ? OR recipient_email = '')
            """, (lost_id, found_id, lost_email))
            if not cursor.fetchone():
                lost_subject = "👀 Wait… someone found something like yours!"
                lost_body = f"""Hey! 👋 Someone reported a found item that could match what you lost. The details look promising, but it's not confirmed yet. Open Finder's Central to compare the clues and securely contact the finder. Fingers crossed! ✨

📦 Your Reported Item: {lost_name.title()} ({lost_cat})
🎯 Matched Found Item: {found_name.title()} ({found_cat})
📍 Location: {found_loc or 'Campus'}
📊 Match Confidence: {score_pct}

View and compare on Finder's Central:
{lost_view_url}

For your security and privacy, personal phone numbers, emails, and student IDs remain protected until identity is verified.

✨ Finder's Central — Campus Lost & Found Hub
"""
                try:
                    sent = send_notification_email(lost_email, lost_subject, lost_body)
                    if sent:
                        cursor.execute("""
                            INSERT OR IGNORE INTO notified_matches
                            (lost_report_id, found_report_id, recipient_email, notified_at)
                            VALUES (?, ?, ?, ?)
                        """, (lost_id, found_id, lost_email, datetime.now().isoformat()))
                        conn.commit()
                except Exception as e:
                    logger.error("Failed to notify lost item owner #%s: %s", lost_id, e)

        # B. NOTIFY FOUND ITEM OWNER
        if is_valid_email_str(found_email):
            cursor.execute("""
                SELECT 1 FROM notified_matches
                WHERE lost_report_id = ? AND found_report_id = ?
                  AND (recipient_email = ? OR recipient_email = '')
            """, (lost_id, found_id, found_email))
            if not cursor.fetchone():
                found_subject = "🔎 Someone might be looking for what you found!"
                found_body = f"""Hey! 👋 Someone reported losing an item that could match what you found. Your report might help reunite someone with their belongings! Check Finder's Central to review the match and respond securely. No pressure until the details line up. 💙

📦 Your Reported Item: {found_name.title()} ({found_cat})
🎯 Matched Lost Item: {lost_name.title()} ({lost_cat})
📍 Location: {lost_loc or 'Campus'}
📊 Match Confidence: {score_pct}

View and compare on Finder's Central:
{found_view_url}

For your security and privacy, personal phone numbers, emails, and student IDs remain protected until identity is verified.

✨ Finder's Central — Campus Lost & Found Hub
"""
                try:
                    sent = send_notification_email(found_email, found_subject, found_body)
                    if sent:
                        cursor.execute("""
                            INSERT OR IGNORE INTO notified_matches
                            (lost_report_id, found_report_id, recipient_email, notified_at)
                            VALUES (?, ?, ?, ?)
                        """, (lost_id, found_id, found_email, datetime.now().isoformat()))
                        conn.commit()
                except Exception as e:
                    logger.error("Failed to notify found item owner #%s: %s", found_id, e)

    conn.close()

# ---------------- HOME / ENTRY ---------------- #

@app.route("/")
def welcome():

    return render_template("welcome.html")


@app.route("/dashboard_guest")
def dashboard_guest():

    session["user"] = "Guest"
    return redirect(url_for("dashboard"))



# ---------------- DASHBOARD ---------------- #

@app.route("/dashboard")
def dashboard():

    if not session.get("user"):
        return redirect(url_for("welcome"))

    user = session.get("user", "Guest")

    conn = sqlite3.connect("lostfound.db")

    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM reports")

    total_reports = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM reports
        WHERE status = 'returned'
    """)

    returned_items = cursor.fetchone()[0]

    
    cursor.execute("""
SELECT DISTINCT item_name
FROM reports
WHERE status = 'returned'
ORDER BY item_name
LIMIT 3
""")

    recent_returns = cursor.fetchall()
    recent_returns = [
    (item[0].title(),)
    for item in recent_returns
]
    conn.close()
    if total_reports > 0:

        recovery_rate = round(
        (returned_items / total_reports) * 100
    )

    else:

        recovery_rate = 0

    return render_template(
        "dashboard.html",
        user=user,
        total_reports=total_reports,
        returned_items=returned_items,
        recovery_rate=recovery_rate,
        recent_returns=recent_returns
    )


def is_safe_redirect_url(target):
    """
    Validates that a redirect target is a safe relative local URL within Finder's Central.
    Rejects external URLs, protocol-relative URLs, schemes, backslashes, and open redirect vectors.
    """
    if not target or not isinstance(target, str):
        return False
    target = target.strip()
    if not target:
        return False
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme or parsed.netloc:
        return False
    if not target.startswith("/") or target.startswith("//") or target.startswith("/\\"):
        return False
    if "\\" in target:
        return False
    return True


# ---------------- LOGIN ---------------- #

@app.route("/login", methods=["GET", "POST"])
def login():

    error = ""
    next_url = request.args.get("next", "").strip() or request.form.get("next", "").strip()
    if not is_safe_redirect_url(next_url):
        next_url = ""

    if request.method == "POST":

        register_number = request.form.get("register_number", "").strip()

        password = request.form.get("password", "")

        conn = sqlite3.connect("lostfound.db")

        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, register_number, password
            FROM users
            WHERE register_number = ?
        """, (register_number,))

        user = cursor.fetchone()

        if user:
            user_id = user[0]
            stored_password = user[2]
            authenticated = False

            # Check if stored password is an already-hashed Werkzeug password
            try:
                if check_password_hash(stored_password, password):
                    authenticated = True
            except Exception:
                authenticated = False

            # Check legacy plaintext password if not matching hash
            if not authenticated and stored_password == password:
                new_hash = generate_password_hash(password)
                cursor.execute("""
                    UPDATE users
                    SET password = ?
                    WHERE id = ?
                """, (new_hash, user_id))
                conn.commit()
                authenticated = True
                logger.info("Upgraded legacy account to Werkzeug password hash.")

            conn.close()

            if authenticated:
                session["user"] = register_number
                if next_url and is_safe_redirect_url(next_url):
                    return redirect(next_url)
                return redirect(url_for("dashboard"))
            else:
                error = "Invalid register number or password"

        else:
            conn.close()
            error = "Invalid register number or password"

    return render_template(
        "login.html",
        error=error,
        next=next_url
    )


# ---------------- SIGNUP ---------------- #

@app.route("/signup", methods=["GET", "POST"])
def signup():

    error = ""

    if request.method == "POST":

        register_number = request.form.get("register_number", "").strip()

        password = request.form.get("password", "")

        if not (
            register_number.startswith("URK")
            and len(register_number) == 11
        ):

            error = "Register number must look like URK25CS1004"

            return render_template(
                "signup.html",
                error=error
            )

        if len(password) < 4:

            error = "Password must be at least 4 characters long."

            return render_template(
                "signup.html",
                error=error
            )

        conn = sqlite3.connect("lostfound.db")

        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM users
            WHERE register_number = ?
        """, (register_number,))

        existing_user = cursor.fetchone()

        if existing_user:

            conn.close()

            error = "User already exists"

            return render_template(
                "signup.html",
                error=error
            )

        hashed_password = generate_password_hash(password)

        cursor.execute("""
            INSERT INTO users
            (
                register_number,
                password
            )

            VALUES (?, ?)
        """,
        (
            register_number,
            hashed_password
        ))

        conn.commit()
        conn.close()

        return redirect(url_for("login"))

    return render_template(
        "signup.html",
        error=error
    )


# ---------------- REPORT ITEM ---------------- #

@app.route("/report", methods=["GET", "POST"])
def report():
    user = session.get("user", "Guest")

    if request.method == "POST":
        timestamp = datetime.now().strftime("%d %b %Y, %I:%M %p")

        item_type = request.form.get("item_type", "").strip()
        item_name = request.form.get("item_name", "").strip().lower()
        category = request.form.get("category", "").strip()
        other_category = request.form.get("other_category", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        contact_raw = request.form.get("contact", "").strip()
        email = request.form.get("email", "").strip()

        # Handle custom category specification
        if category == "Other" and other_category:
            category = other_category
        elif not category and other_category:
            category = other_category

        # Validate mandatory text inputs
        if not item_type or not item_name or not category or not description or not location:
            return render_template(
                "report.html",
                error="Please complete all required fields (Item Type, Title, Category, Description, and Location).",
                form_data=request.form,
                user=user
            ), 400

        # Validate and normalize 10-digit phone number
        clean_contact = re.sub(r"[^\d]", "", contact_raw)
        if clean_contact.startswith("91") and len(clean_contact) == 12:
            clean_contact = clean_contact[2:]

        if len(clean_contact) != 10:
            return render_template(
                "report.html",
                error="Please provide a valid 10-digit mobile phone number (digits only).",
                form_data=request.form,
                user=user
            ), 400
        contact = clean_contact

        # Validate email address format
        if not email or "@" not in email or "." not in email:
            return render_template(
                "report.html",
                error="Please provide a valid contact email address.",
                form_data=request.form,
                user=user
            ), 400

        # Validate and store optional uploaded image
        image = request.files.get("image")
        image_filename = ""

        if image and image.filename:
            is_valid, unique_name, err_msg = validate_uploaded_image(image)
            if not is_valid:
                return render_template(
                    "report.html",
                    error=err_msg,
                    form_data=request.form,
                    user=user
                ), 400
            image_filename = unique_name
            image.save(
                os.path.join(
                    app.config["UPLOAD_FOLDER"],
                    image_filename
                )
            )

        current_user = session.get("user")
        is_student = bool(current_user and current_user != "Guest")

        claim_token = None
        claim_token_hash = None
        claim_token_expires_at = None
        claim_url = None
        email_sent = False

        if is_student:
            owner = current_user
            verified = 1
        else:
            claim_token = secrets.token_urlsafe(32)
            claim_token_hash = hashlib.sha256(claim_token.encode('utf-8')).hexdigest()
            claim_token_expires_at = (datetime.now() + timedelta(days=30)).isoformat()
            owner = f"guest_{secrets.token_hex(6)}"
            verified = 0
            claim_url = url_for("claim_guest_report", token=claim_token, _external=True)

            # Send claim verification email to guest if mail configured
            email_subject = "Your Finder's Central Report Claim Link 🔑"
            email_body = f"""Hello! 👋

Thank you for reporting an item on Finder's Central.

📦 Item: {item_name.title()} ({item_type})
🏷️ Category: {category}

As a campus visitor/guest, use your private claim link below to verify your report and manage its status:
{claim_url}

Keep this link safe! You will need it to update your report or mark it as returned.

🔍 Finder's Central — Campus Lost & Found Hub
"""
            email_sent = send_notification_email(email, email_subject, email_body)

        conn = sqlite3.connect("lostfound.db")
        cursor = conn.cursor()

        # Step 1: Save and commit report record first
        cursor.execute("""
            INSERT INTO reports
            (
                item_type,
                item_name,
                category,
                description,
                location,
                contact,
                email,
                image,
                status,
                timestamp,
                owner,
                claim_token_hash,
                claim_token_expires_at,
                verified
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            item_type,
            item_name,
            category,
            description,
            location,
            contact,
            email,
            image_filename,
            "active",
            timestamp,
            owner,
            claim_token_hash,
            claim_token_expires_at,
            verified
        ))
        new_report_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Step 2: Track newly created report in guest session
        if not is_student:
            claimed = session.get("claimed_reports", [])
            if new_report_id not in claimed:
                claimed.append(new_report_id)
                session["claimed_reports"] = claimed
                session.modified = True

        # Step 3: Run unified multi-attribute + AI TF-IDF matching pipeline
        new_report_tuple = (
            new_report_id, item_type, item_name, category, description,
            location, contact, email, "active", timestamp, owner,
            image_filename, claim_token_hash, claim_token_expires_at, verified
        )
        matches = find_matching_reports(new_report_tuple, db_path="lostfound.db", threshold=SUGGESTION_THRESHOLD)
        if matches:
            try:
                notify_matches(new_report_tuple, matches, db_path="lostfound.db")
            except Exception as e:
                logger.error("Error executing match notification pipeline: %s", type(e).__name__)

        # Step 4: Display response
        if matches:
            return render_template(
                "match_found.html",
                matches=matches,
                report=matches[0]["report"],
                new_report_id=new_report_id,
                new_report_name=item_name.title(),
                new_report_type=item_type,
                is_guest=not is_student,
                claim_token=claim_token,
                claim_url=claim_url,
                email_sent=email_sent,
                email=email,
                user=session.get("user", "Guest")
            )

        if not is_student:
            return render_template(
                "guest_confirmation.html",
                report_id=new_report_id,
                item_name=item_name.title(),
                item_type=item_type,
                category=category,
                claim_token=claim_token,
                claim_url=claim_url,
                email_sent=email_sent,
                email=email,
                user="Guest"
            )

        return redirect(url_for("reports"))

    return render_template(
        "report.html",
        user=user
    )


# ---------------- SEE MATCHES (DEDICATED PERSONALIZED MATCHES) ---------------- #

@app.route("/matches")
def matches():
    """
    Dedicated See Matches route:
    Displays personalized matches comparing only the current user's own active reports
    against eligible, active campus listings of the opposite type.
    - Authenticated students: sources are active reports where owner == user.
    - Campus guests: sources are active reports tracked in session claimed_reports.
    - Excludes self-reports, same-owner reports, resolved reports, and contradictions.
    - Server-side filtered with no exposure of other users' pairings.
    """
    if not session.get("user"):
        session["user"] = "Guest"

    user = session.get("user", "Guest")
    is_student = bool(user and user != "Guest")
    claimed_ids = list(session.get("claimed_reports", []))

    # Optional: allow a guest to supply a claim token in the query string
    token_param = request.args.get("claim_token", "").strip()
    if token_param:
        if "/guest/claim/" in token_param:
            token_param = token_param.split("/guest/claim/")[-1].split("?")[0].split("#")[0].strip()
        elif "/guest/manage/" in token_param:
            token_param = token_param.split("/guest/manage/")[-1].split("?")[0].split("#")[0].strip()
        token_hash = hashlib.sha256(token_param.encode('utf-8')).hexdigest()
        conn = sqlite3.connect("lostfound.db")
        cur = conn.cursor()
        cur.execute("SELECT id FROM reports WHERE claim_token_hash = ? AND status = 'active'", (token_hash,))
        token_row = cur.fetchone()
        conn.close()
        if token_row and token_row[0] not in claimed_ids:
            claimed_ids.append(token_row[0])
            session["claimed_reports"] = claimed_ids
            session.modified = True

    conn = sqlite3.connect("lostfound.db")
    cursor = conn.cursor()

    user_active_reports = []
    if is_student:
        cursor.execute("""
            SELECT id, item_type, item_name, category, description, location
            FROM reports
            WHERE owner = ? AND status = 'active'
            ORDER BY id DESC
        """, (user,))
        user_active_reports = cursor.fetchall()
    elif claimed_ids:
        placeholders = ",".join("?" for _ in claimed_ids)
        cursor.execute(f"""
            SELECT id, item_type, item_name, category, description, location
            FROM reports
            WHERE id IN ({placeholders}) AND status = 'active'
            ORDER BY id DESC
        """, claimed_ids)
        user_active_reports = cursor.fetchall()

    conn.close()

    user_has_reports = len(user_active_reports) > 0
    personalized_matches = get_personalized_matches(user, claimed_ids=claimed_ids, db_path="lostfound.db", limit=20)
    connect_form_data = session.pop("connect_form_data", None)

    return render_template(
        "matches.html",
        user=user,
        is_student=is_student,
        user_active_reports=user_active_reports,
        user_has_reports=user_has_reports,
        personalized_matches=personalized_matches,
        matches_count=len(personalized_matches),
        connect_form_data=connect_form_data
    )


# ---------------- VIEW REPORTS ---------------- #

@app.route("/reports")
def reports():
    user = session.get("user", "Guest")
    is_student = bool(user and user != "Guest")
    claimed_ids = session.get("claimed_reports", [])

    conn = sqlite3.connect("lostfound.db")

    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM reports

        ORDER BY

        CASE
            WHEN status = 'active' THEN 0
            ELSE 1
        END,

        id DESC
    """)

    all_reports = cursor.fetchall()

    user_active_reports = []
    if is_student:
        cursor.execute("""
            SELECT id, item_type, item_name, category FROM reports
            WHERE owner = ? AND status = 'active'
            ORDER BY id DESC
        """, (user,))
        user_active_reports = cursor.fetchall()
    elif claimed_ids:
        placeholders = ",".join("?" for _ in claimed_ids)
        cursor.execute(f"""
            SELECT id, item_type, item_name, category FROM reports
            WHERE id IN ({placeholders}) AND status = 'active'
            ORDER BY id DESC
        """, claimed_ids)
        user_active_reports = cursor.fetchall()

    conn.close()

    user_has_reports = len(user_active_reports) > 0
    mail_configured = bool(app.config.get("MAIL_USERNAME") and app.config.get("MAIL_PASSWORD"))
    connect_form_data = session.pop("connect_form_data", None)

    return render_template(
        "reports.html",
        reports=all_reports,
        user=user,
        user_active_reports=user_active_reports,
        user_has_reports=user_has_reports,
        personalized_matches=[],
        suggested_matches=[],
        mail_configured=mail_configured,
        connect_form_data=connect_form_data
    )


# ---------------- MARK RETURNED ---------------- #

# ---------------- MARK RETURNED ---------------- #

# ---------------- GUEST CLAIM & MANAGEMENT ROUTES ---------------- #

@app.route("/guest/claim/<token>")
def claim_guest_report(token):
    # Strip URL prefix if full URL was passed
    if "/guest/claim/" in token:
        token = token.split("/guest/claim/")[-1].split("?")[0].split("#")[0].strip()
    elif "/guest/manage/" in token:
        token = token.split("/guest/manage/")[-1].split("?")[0].split("#")[0].strip()

    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    now_iso = datetime.now().isoformat()

    conn = sqlite3.connect("lostfound.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, claim_token_expires_at, verified
        FROM reports
        WHERE claim_token_hash = ?
    """, (token_hash,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return render_template(
            "guest_manage.html",
            error="Invalid or unrecognized claim token. This report could not be found.",
            user=session.get("user", "Guest")
        ), 404

    report_id, expires_at, verified = row
    if expires_at and expires_at < now_iso:
        conn.close()
        return render_template(
            "guest_manage.html",
            error="This claim link has expired. Guest claim links are valid for 30 days.",
            user=session.get("user", "Guest")
        ), 410

    # Mark report as verified
    cursor.execute("UPDATE reports SET verified = 1 WHERE id = ?", (report_id,))
    conn.commit()
    conn.close()

    # Session isolation:
    # If a student is logged in, do NOT overwrite session or mix guest claim into student identity.
    current_user = session.get("user")
    if not current_user:
        session["user"] = "Guest"
        claimed = session.get("claimed_reports", [])
        if report_id not in claimed:
            claimed.append(report_id)
            session["claimed_reports"] = claimed
            session.modified = True
    elif current_user == "Guest":
        claimed = session.get("claimed_reports", [])
        if report_id not in claimed:
            claimed.append(report_id)
            session["claimed_reports"] = claimed
            session.modified = True

    return redirect(url_for("guest_manage_report", token=token))


@app.route("/guest/manage/<token>")
def guest_manage_report(token):
    # Strip URL prefix if full URL was passed
    if "/guest/claim/" in token:
        token = token.split("/guest/claim/")[-1].split("?")[0].split("#")[0].strip()
    elif "/guest/manage/" in token:
        token = token.split("/guest/manage/")[-1].split("?")[0].split("#")[0].strip()

    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    now_iso = datetime.now().isoformat()

    conn = sqlite3.connect("lostfound.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT *
        FROM reports
        WHERE claim_token_hash = ?
    """, (token_hash,))
    report = cursor.fetchone()

    if not report:
        conn.close()
        return render_template(
            "guest_manage.html",
            error="Invalid or unrecognized claim token. This report could not be found.",
            user=session.get("user", "Guest")
        ), 404

    expires_at = report[13] if len(report) > 13 else None
    if expires_at and expires_at < now_iso:
        conn.close()
        return render_template(
            "guest_manage.html",
            error="This claim link has expired. Guest claim links are valid for 30 days.",
            user=session.get("user", "Guest")
        ), 410

    # Session isolation:
    current_user = session.get("user")
    if not current_user:
        session["user"] = "Guest"
        claimed = session.get("claimed_reports", [])
        if report[0] not in claimed:
            claimed.append(report[0])
            session["claimed_reports"] = claimed
            session.modified = True
    elif current_user == "Guest":
        claimed = session.get("claimed_reports", [])
        if report[0] not in claimed:
            claimed.append(report[0])
            session["claimed_reports"] = claimed
            session.modified = True

    # Find potential matches for this report
    rep_tuple = (report[0], report[1], report[2], report[3], report[4], report[5])
    matches = find_matching_reports(rep_tuple, db_path="lostfound.db", threshold=SUGGESTION_THRESHOLD)

    # Incoming requests where this report is target
    cursor.execute("""
        SELECT cr.id, cr.source_report_id, cr.target_report_id, cr.requester_type, cr.status,
               cr.message, cr.response_note, cr.contact_info, cr.created_at, cr.updated_at,
               sr.item_name, sr.item_type, sr.category, sr.location,
               tr.item_name, tr.item_type,
               sr.contact, sr.email
        FROM connection_requests cr
        JOIN reports sr ON cr.source_report_id = sr.id
        JOIN reports tr ON cr.target_report_id = tr.id
        WHERE cr.target_report_id = ?
        ORDER BY cr.id DESC
    """, (report[0],))
    incoming_raw = cursor.fetchall()
    incoming_requests = []
    for req in incoming_raw:
        r = list(req)
        if r[4] != 'accepted':
            r[16] = None
            r[17] = None
            r[7] = None
        incoming_requests.append(tuple(r))

    # Outgoing requests where this report is source
    cursor.execute("""
        SELECT cr.id, cr.source_report_id, cr.target_report_id, cr.recipient_type, cr.status,
               cr.message, cr.response_note, cr.contact_info, cr.created_at, cr.updated_at,
               sr.item_name, sr.item_type,
               tr.item_name, tr.item_type, tr.location,
               tr.contact, tr.email
        FROM connection_requests cr
        JOIN reports sr ON cr.source_report_id = sr.id
        JOIN reports tr ON cr.target_report_id = tr.id
        WHERE cr.source_report_id = ?
        ORDER BY cr.id DESC
    """, (report[0],))
    outgoing_raw = cursor.fetchall()
    outgoing_requests = []
    for req in outgoing_raw:
        r = list(req)
        if r[4] != 'accepted':
            r[15] = None
            r[16] = None
            r[6] = None
        outgoing_requests.append(tuple(r))

    conn.close()

    return render_template(
        "guest_manage.html",
        report=report,
        matches=matches,
        incoming_requests=incoming_requests,
        outgoing_requests=outgoing_requests,
        token=token,
        user=session.get("user", "Guest"),
        is_student=bool(current_user and current_user != "Guest")
    )


@app.route("/guest/mark_returned/<token>", methods=["POST"])
def guest_mark_returned_token(token):
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    now_iso = datetime.now().isoformat()

    conn = sqlite3.connect("lostfound.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, claim_token_expires_at
        FROM reports
        WHERE claim_token_hash = ?
    """, (token_hash,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        abort(403)

    report_id, expires_at = row
    if expires_at and expires_at < now_iso:
        conn.close()
        abort(403)

    cursor.execute("UPDATE reports SET status = 'returned' WHERE id = ?", (report_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("guest_manage_report", token=token))


@app.route("/guest/delete_report/<token>", methods=["POST"])
def guest_delete_report_token(token):
    token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    now_iso = datetime.now().isoformat()

    conn = sqlite3.connect("lostfound.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, claim_token_expires_at
        FROM reports
        WHERE claim_token_hash = ?
    """, (token_hash,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        abort(403)

    report_id, expires_at = row
    if expires_at and expires_at < now_iso:
        conn.close()
        abort(403)

    cursor.execute("DELETE FROM reports WHERE id = ?", (report_id,))
    cursor.execute("DELETE FROM notified_matches WHERE lost_report_id = ? OR found_report_id = ?", (report_id, report_id))
    cursor.execute("DELETE FROM connection_requests WHERE source_report_id = ? OR target_report_id = ?", (report_id, report_id))
    conn.commit()
    conn.close()

    # Remove from session
    claimed = session.get("claimed_reports", [])
    if report_id in claimed:
        claimed.remove(report_id)
        session["claimed_reports"] = claimed
        session.modified = True

    return render_template(
        "guest_manage.html",
        message="Your guest report has been permanently deleted.",
        user="Guest"
    )


@app.route("/guest/my_reports")
def guest_my_reports():
    claimed_ids = session.get("claimed_reports", [])
    active_reports = []
    returned_reports = []
    incoming_requests = []
    outgoing_requests = []

    if claimed_ids:
        conn = sqlite3.connect("lostfound.db")
        cursor = conn.cursor()
        placeholders = ",".join("?" for _ in claimed_ids)
        cursor.execute(f"""
            SELECT * FROM reports
            WHERE id IN ({placeholders}) AND status = 'active'
            ORDER BY id DESC
        """, claimed_ids)
        active_reports = cursor.fetchall()

        cursor.execute(f"""
            SELECT * FROM reports
            WHERE id IN ({placeholders}) AND status = 'returned'
            ORDER BY id DESC
        """, claimed_ids)
        returned_reports = cursor.fetchall()

        cursor.execute(f"""
            SELECT cr.id, cr.source_report_id, cr.target_report_id, cr.requester_type, cr.status,
                   cr.message, cr.response_note, cr.contact_info, cr.created_at, cr.updated_at,
                   sr.item_name, sr.item_type, sr.category, sr.location,
                   tr.item_name, tr.item_type,
                   sr.contact, sr.email
            FROM connection_requests cr
            JOIN reports sr ON cr.source_report_id = sr.id
            JOIN reports tr ON cr.target_report_id = tr.id
            WHERE cr.target_report_id IN ({placeholders})
            ORDER BY cr.id DESC
        """, claimed_ids)
        incoming_raw = cursor.fetchall()
        for req in incoming_raw:
            r = list(req)
            if r[4] != 'accepted':
                r[16] = None
                r[17] = None
                r[7] = None
            incoming_requests.append(tuple(r))

        cursor.execute(f"""
            SELECT cr.id, cr.source_report_id, cr.target_report_id, cr.recipient_type, cr.status,
                   cr.message, cr.response_note, cr.contact_info, cr.created_at, cr.updated_at,
                   sr.item_name, sr.item_type,
                   tr.item_name, tr.item_type, tr.location,
                   tr.contact, tr.email
            FROM connection_requests cr
            JOIN reports sr ON cr.source_report_id = sr.id
            JOIN reports tr ON cr.target_report_id = tr.id
            WHERE cr.source_report_id IN ({placeholders})
            ORDER BY cr.id DESC
        """, claimed_ids)
        outgoing_raw = cursor.fetchall()
        for req in outgoing_raw:
            r = list(req)
            if r[4] != 'accepted':
                r[15] = None
                r[16] = None
                r[6] = None
            outgoing_requests.append(tuple(r))

        conn.close()

    return render_template(
        "guest_my_reports.html",
        active_reports=active_reports,
        returned_reports=returned_reports,
        incoming_requests=incoming_requests,
        outgoing_requests=outgoing_requests,
        active_count=len(active_reports),
        returned_count=len(returned_reports),
        user="Guest"
    )


@app.route("/guest/claim_token", methods=["POST"])
def guest_claim_token_input():
    token_input = request.form.get("claim_token", "").strip()
    if not token_input:
        return redirect(url_for("guest_my_reports"))

    # Extract token if user pasted full URL
    if "/guest/claim/" in token_input:
        token_input = token_input.split("/guest/claim/")[-1].split("?")[0].split("#")[0].strip()
    elif "/guest/manage/" in token_input:
        token_input = token_input.split("/guest/manage/")[-1].split("?")[0].split("#")[0].strip()

    token_hash = hashlib.sha256(token_input.encode('utf-8')).hexdigest()
    now_iso = datetime.now().isoformat()
    conn = sqlite3.connect("lostfound.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, claim_token_expires_at FROM reports WHERE claim_token_hash = ?", (token_hash,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return render_template(
            "guest_my_reports.html",
            error="No report found with that claim token. Please double-check your link or code.",
            active_reports=[],
            returned_reports=[],
            active_count=0,
            returned_count=0,
            user="Guest"
        ), 404

    report_id, expires_at = row
    if expires_at and expires_at < now_iso:
        return render_template(
            "guest_my_reports.html",
            error="This claim link has expired. Guest claim links are valid for 30 days.",
            active_reports=[],
            returned_reports=[],
            active_count=0,
            returned_count=0,
            user="Guest"
        ), 410

    return redirect(url_for("claim_guest_report", token=token_input))


# ---------------- MARK RETURNED ---------------- #

@app.route("/mark_returned/<int:report_id>", methods=["POST"])
def mark_returned(report_id):
    current_user = session.get("user")
    is_student = bool(current_user and current_user != "Guest")
    claimed_ids = session.get("claimed_reports", [])

    conn = sqlite3.connect("lostfound.db")
    cursor = conn.cursor()
    cursor.execute("SELECT owner FROM reports WHERE id = ?", (report_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        abort(404)

    owner = row[0]
    # Enforce strict server-side report ownership:
    # Authenticated students may only mark returned their own reports (owner == current_user).
    # Guests may only mark returned guest reports in their session claimed_reports.
    if is_student:
        if owner != current_user:
            conn.close()
            logger.warning("Denied unauthorized mark_returned by student %s on report #%d owned by %s", current_user, report_id, owner)
            abort(403)
    else:
        if report_id not in claimed_ids or (owner and not owner.startswith("guest_") and owner != "Guest"):
            conn.close()
            logger.warning("Denied unauthorized guest mark_returned on report #%d", report_id)
            abort(403)

    now_str = datetime.now().strftime("%d %b %Y, %I:%M %p")
    cursor.execute("UPDATE reports SET status = 'returned' WHERE id = ?", (report_id,))
    conn.commit()
    conn.close()

    if is_student:
        return redirect(url_for("my_reports"))
    return redirect(url_for("guest_my_reports"))


# ---------------- DELETE REPORT ---------------- #

@app.route("/delete_report/<int:report_id>", methods=["POST"])
def delete_report(report_id):
    current_user = session.get("user")
    is_student = bool(current_user and current_user != "Guest")
    claimed_ids = session.get("claimed_reports", [])

    conn = sqlite3.connect("lostfound.db")
    cursor = conn.cursor()
    cursor.execute("SELECT owner FROM reports WHERE id = ?", (report_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        abort(404)

    owner = row[0]
    # Enforce strict server-side report ownership:
    # Authenticated students may only delete their own reports (owner == current_user).
    # Guests may only delete guest reports in their session claimed_reports.
    if is_student:
        if owner != current_user:
            conn.close()
            logger.warning("Denied unauthorized delete_report by student %s on report #%d owned by %s", current_user, report_id, owner)
            abort(403)
    else:
        if report_id not in claimed_ids or (owner and not owner.startswith("guest_") and owner != "Guest"):
            conn.close()
            logger.warning("Denied unauthorized guest delete_report on report #%d", report_id)
            abort(403)

    cursor.execute("DELETE FROM reports WHERE id = ?", (report_id,))
    cursor.execute("DELETE FROM notified_matches WHERE lost_report_id = ? OR found_report_id = ?", (report_id, report_id))
    cursor.execute("DELETE FROM connection_requests WHERE source_report_id = ? OR target_report_id = ?", (report_id, report_id))
    conn.commit()
    conn.close()

    if is_student:
        return redirect(url_for("my_reports"))
    if report_id in claimed_ids:
        claimed_ids.remove(report_id)
        session["claimed_reports"] = claimed_ids
        session.modified = True
    return redirect(url_for("guest_my_reports"))


# ---------------- LOGOUT ---------------- #

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("welcome"))


@app.route("/my_reports")
def my_reports():

    current_user = session.get("user")
    if not current_user or current_user == "Guest":
        return redirect(url_for("guest_my_reports"))

    conn = sqlite3.connect("lostfound.db")

    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM reports
        WHERE owner = ? AND status = 'active'
        ORDER BY id DESC
    """, (current_user,))

    active_reports = cursor.fetchall()

    cursor.execute("""
        SELECT * FROM reports
        WHERE owner = ? AND status = 'returned'
        ORDER BY id DESC
    """, (current_user,))

    returned_reports = cursor.fetchall()
    active_count = len(active_reports)
    returned_count = len(returned_reports)

    # Incoming connection requests (where current student is recipient)
    cursor.execute("""
        SELECT cr.id, cr.source_report_id, cr.target_report_id, cr.requester_type, cr.status,
               cr.message, cr.response_note, cr.contact_info, cr.created_at, cr.updated_at,
               sr.item_name, sr.item_type, sr.category, sr.location,
               tr.item_name, tr.item_type,
               sr.contact, sr.email
        FROM connection_requests cr
        JOIN reports sr ON cr.source_report_id = sr.id
        JOIN reports tr ON cr.target_report_id = tr.id
        WHERE (cr.recipient_id = ? AND cr.recipient_type = 'student')
           OR cr.target_report_id IN (SELECT id FROM reports WHERE owner = ?)
        ORDER BY cr.id DESC
    """, (current_user, current_user))
    incoming_raw = cursor.fetchall()
    incoming_requests = []
    for req in incoming_raw:
        r = list(req)
        if r[4] != 'accepted':
            r[16] = None
            r[17] = None
            r[7] = None
        incoming_requests.append(tuple(r))

    # Outgoing connection requests (where current student is requester)
    cursor.execute("""
        SELECT cr.id, cr.source_report_id, cr.target_report_id, cr.recipient_type, cr.status,
               cr.message, cr.response_note, cr.contact_info, cr.created_at, cr.updated_at,
               sr.item_name, sr.item_type,
               tr.item_name, tr.item_type, tr.location,
               tr.contact, tr.email
        FROM connection_requests cr
        JOIN reports sr ON cr.source_report_id = sr.id
        JOIN reports tr ON cr.target_report_id = tr.id
        WHERE (cr.requester_id = ? AND cr.requester_type = 'student')
           OR cr.source_report_id IN (SELECT id FROM reports WHERE owner = ?)
        ORDER BY cr.id DESC
    """, (current_user, current_user))
    outgoing_raw = cursor.fetchall()
    outgoing_requests = []
    for req in outgoing_raw:
        r = list(req)
        if r[4] != 'accepted':
            r[15] = None
            r[16] = None
            r[6] = None
        outgoing_requests.append(tuple(r))

    conn.close()

    return render_template(
        "my_reports.html",
        active_reports=active_reports,
        returned_reports=returned_reports,
        incoming_requests=incoming_requests,
        outgoing_requests=outgoing_requests,
        active_count=active_count,
        returned_count=returned_count,
        user=current_user
    )


# ---------------- CONNECTION REQUESTS WORKFLOW ---------------- #

@app.route("/request_connection", methods=["POST"])
def request_connection():
    current_user = session.get("user")
    is_student = bool(current_user and current_user != "Guest")
    claimed_ids = session.get("claimed_reports", [])

    source_report_id = request.form.get("source_report_id", type=int)
    target_report_id = request.form.get("target_report_id", type=int)
    claim_token = request.form.get("claim_token", "").strip()
    message = request.form.get("message", "").strip()
    contact_info = request.form.get("contact_info", "").strip()

    def _handle_conn_error(reason):
        session["connect_form_data"] = {
            "message": message,
            "contact_info": contact_info,
            "source_report_id": source_report_id or "",
            "target_report_id": target_report_id or "",
            "claim_token": claim_token or ""
        }
        flash(reason, "error")
        if request.referrer and ("/reports" in request.referrer or "/guest/" in request.referrer):
            return redirect(request.referrer)
        return redirect(url_for("reports"))

    # Clean claim token if full URL was pasted
    if claim_token:
        if "/guest/claim/" in claim_token:
            claim_token = claim_token.split("/guest/claim/")[-1].split("?")[0].split("#")[0].strip()
        elif "/guest/manage/" in claim_token:
            claim_token = claim_token.split("/guest/manage/")[-1].split("?")[0].split("#")[0].strip()

    # Automatically resolve source_report_id from claim_token if omitted
    if not source_report_id and claim_token:
        token_hash = hashlib.sha256(claim_token.encode('utf-8')).hexdigest()
        now_iso = datetime.now().isoformat()
        conn_token = sqlite3.connect("lostfound.db")
        c_token = conn_token.cursor()
        c_token.execute("""
            SELECT id FROM reports
            WHERE claim_token_hash = ? AND status = 'active'
              AND (claim_token_expires_at IS NULL OR claim_token_expires_at >= ?)
        """, (token_hash, now_iso))
        t_row = c_token.fetchone()
        conn_token.close()
        if t_row:
            source_report_id = t_row[0]

    if not target_report_id:
        return _handle_conn_error("Target report is required.")

    if not source_report_id:
        return _handle_conn_error("Please select a valid matching report or provide your guest claim token.")

    if source_report_id == target_report_id:
        return _handle_conn_error("Cannot send a connection request between the same report.")

    if not message:
        return _handle_conn_error("Please provide an identifying clue or verification message to help verify ownership.")

    conn = sqlite3.connect("lostfound.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM reports WHERE id = ?", (source_report_id,))
    source_report = cursor.fetchone()

    cursor.execute("SELECT * FROM reports WHERE id = ?", (target_report_id,))
    target_report = cursor.fetchone()

    if not source_report or not target_report:
        conn.close()
        return _handle_conn_error("One or both reports could not be found.")

    # Both reports must be active
    if source_report[8] != "active" or target_report[8] != "active":
        conn.close()
        return _handle_conn_error("Connection requests can only be sent for active, unreturned reports.")

    # Must be complementary item types
    if source_report[1] == target_report[1]:
        conn.close()
        return _handle_conn_error("Connection requests must be between a Lost item and a Found item.")

    # Verify ownership of source_report
    requester_type = None
    requester_id = None

    if is_student and source_report[10] == current_user:
        requester_type = "student"
        requester_id = current_user
    else:
        if claim_token:
            token_hash = hashlib.sha256(claim_token.encode('utf-8')).hexdigest()
            now_iso = datetime.now().isoformat()
            if source_report[12] == token_hash and (not source_report[13] or source_report[13] >= now_iso):
                if not session.get("user"):
                    session["user"] = "Guest"
                if source_report_id not in claimed_ids:
                    claimed_ids.append(source_report_id)
                    session["claimed_reports"] = claimed_ids
                    session.modified = True
                requester_type = "guest"
                requester_id = source_report[10]
        elif source_report_id in claimed_ids:
            if not session.get("user"):
                session["user"] = "Guest"
            requester_type = "guest"
            requester_id = source_report[10]

    if not requester_type:
        conn.close()
        return _handle_conn_error("You are not authorized to send requests on behalf of this report.")

    # Determine recipient
    target_owner = target_report[10]
    if target_owner and (target_owner.startswith("guest_") or target_owner == "Guest"):
        recipient_type = "guest"
        recipient_id = target_owner
    else:
        recipient_type = "student"
        recipient_id = target_owner

    # Prevent self-requests (users cannot send connection requests to their own items)
    is_same_owner = False
    if requester_id == recipient_id:
        is_same_owner = True
    elif source_report[10] and source_report[10] == target_report[10]:
        is_same_owner = True
    elif not is_student and (source_report_id in claimed_ids and target_report_id in claimed_ids):
        is_same_owner = True

    if is_same_owner:
        conn.close()
        logger.warning("Rejected self-connection request for user %s on report #%d", requester_id, target_report_id)
        return _handle_conn_error("Cannot send a connection request between reports owned by the same person.")

    # Check for duplicate pending or accepted request
    cursor.execute("""
        SELECT id, status FROM connection_requests
        WHERE ((source_report_id = ? AND target_report_id = ?)
            OR (source_report_id = ? AND target_report_id = ?))
          AND status IN ('pending', 'accepted')
    """, (source_report_id, target_report_id, target_report_id, source_report_id))
    existing = cursor.fetchone()

    if existing:
        conn.close()
        return _handle_conn_error(f"A connection request between these reports is already {existing[1]}.")

    now_str = datetime.now().strftime("%d %b %Y, %I:%M %p")
    cursor.execute("""
        INSERT INTO connection_requests
        (source_report_id, target_report_id, requester_type, requester_id,
         recipient_type, recipient_id, status, message, contact_info, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
    """, (source_report_id, target_report_id, requester_type, requester_id,
          recipient_type, recipient_id, message, contact_info, now_str, now_str))

    new_req_id = cursor.lastrowid
    conn.commit()

    # Confirm the server actually saved the request before displaying success
    cursor.execute("SELECT id, status FROM connection_requests WHERE id = ?", (new_req_id,))
    saved_check = cursor.fetchone()
    if not saved_check or saved_check[1] != 'pending':
        conn.close()
        logger.error("Failed to verify saved connection request #%s", new_req_id)
        return _handle_conn_error("Failed to save connection request to database. Please try again.")

    # Attempt to dispatch connection request email alert if target email is available
    target_email = target_report[7]
    if target_email:
        reports_link = url_for('reports', _external=True) if has_request_context() else "/reports"
        subj = f"New Connection Request for {target_report[2].title()} — Finder's Central"
        body = f"""Hello! 👋

Someone submitted a connection request regarding your report on Finder's Central.

📦 Your Item: {target_report[2].title()} ({target_report[1]})
🏷️ Category: {target_report[3]}

Verification Clue:
"{message}"

To review this request and coordinate verification or return, please visit Finder's Central:
{reports_link}

Personal contact information remains protected until you explicitly accept the request.

🔍 Finder's Central — Campus Lost & Found Hub
"""
        send_notification_email(target_email, subj, body)

    conn.close()

    session.pop("connect_form_data", None)
    logger.info("Connection request #%d created and verified between report #%d and #%d", new_req_id, source_report_id, target_report_id)
    flash("Request sent! We'll let you know when they respond.", "success")

    if requester_type == "student":
        return redirect(url_for("my_reports"))
    elif claim_token:
        return redirect(url_for("guest_manage_report", token=claim_token))
    return redirect(url_for("guest_my_reports"))


def _redirect_after_connection_action(current_user, token=None):
    """Safely redirects user to their appropriate report management view after an action."""
    if token:
        clean_token = token
        if "/guest/claim/" in clean_token:
            clean_token = clean_token.split("/guest/claim/")[-1].split("?")[0].split("#")[0].strip()
        elif "/guest/manage/" in clean_token:
            clean_token = clean_token.split("/guest/manage/")[-1].split("?")[0].split("#")[0].strip()
        return redirect(url_for("guest_manage_report", token=clean_token))
    if current_user and current_user != "Guest":
        return redirect(url_for("my_reports"))
    return redirect(url_for("guest_my_reports"))


def check_connection_request_authorization(req_id, current_user, token=None, claimed_ids=None):
    """
    Checks if the current user (student or guest) is authorized to accept or decline
    the connection request for target_report.
    Returns: (is_authorized, req_row, target_report, error_reason)
    """
    if claimed_ids is None:
        claimed_ids = session.get("claimed_reports", [])

    conn = sqlite3.connect("lostfound.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT cr.id, cr.source_report_id, cr.target_report_id, cr.requester_type, cr.requester_id,
               cr.recipient_type, cr.recipient_id, cr.status, cr.message, cr.response_note, cr.contact_info
        FROM connection_requests cr
        WHERE cr.id = ?
    """, (req_id,))
    req_row = cursor.fetchone()

    if not req_row:
        conn.close()
        return False, None, None, "not_found"

    target_report_id = req_row[2]
    cursor.execute("SELECT * FROM reports WHERE id = ?", (target_report_id,))
    target_report = cursor.fetchone()
    conn.close()

    if not target_report:
        return False, req_row, None, "target_report_not_found"

    cr_status = req_row[7]
    if cr_status != "pending":
        return False, req_row, target_report, f"already_{cr_status}"

    # Authorization Check
    is_authorized = False

    # 1. Student authorization: owns target report or is recorded recipient
    if current_user and current_user != "Guest":
        if target_report[10] == current_user or req_row[6] == current_user:
            is_authorized = True

    # 2. Guest token authorization
    if not is_authorized and token:
        clean_token = token
        if "/guest/claim/" in clean_token:
            clean_token = clean_token.split("/guest/claim/")[-1].split("?")[0].split("#")[0].strip()
        elif "/guest/manage/" in clean_token:
            clean_token = clean_token.split("/guest/manage/")[-1].split("?")[0].split("#")[0].strip()
        token_hash = hashlib.sha256(clean_token.encode('utf-8')).hexdigest()
        now_iso = datetime.now().isoformat()
        if target_report[12] == token_hash and (not target_report[13] or target_report[13] >= now_iso):
            is_authorized = True

    # 3. Guest session authorization: report is in claimed_reports or guest owner matches
    if not is_authorized:
        if target_report_id in claimed_ids:
            is_authorized = True
        elif current_user and current_user != "Guest" and target_report[10] == current_user:
            is_authorized = True

    if not is_authorized:
        return False, req_row, target_report, "unauthorized"

    return True, req_row, target_report, None


@app.route("/connection_request/<int:req_id>/accept", methods=["GET", "POST"])
def accept_connection_request(req_id):
    current_user = session.get("user")
    token = request.form.get("claim_token") or request.form.get("token") or request.args.get("token") or request.args.get("claim_token") or ""

    if request.method == "GET":
        return _redirect_after_connection_action(current_user, token)

    is_authorized, req_row, target_report, error_reason = check_connection_request_authorization(req_id, current_user, token=token)

    if not is_authorized:
        if error_reason == "not_found":
            flash("Connection request not found.", "error")
        elif error_reason in ("already_accepted", "already_declined"):
            status_word = error_reason.split("_")[1]
            flash(f"This connection request has already been {status_word}.", "info")
        else:
            logger.warning("Denied unauthorized accept on connection request #%d by %s", req_id, current_user)
            flash("You do not have permission to manage this connection request.", "error")
        return _redirect_after_connection_action(current_user, token)

    response_note = request.form.get("response_note", "").strip() or "Accepted. Please reach out to coordinate return."
    now_str = datetime.now().strftime("%d %b %Y, %I:%M %p")

    conn = sqlite3.connect("lostfound.db")
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE connection_requests
        SET status = 'accepted', response_note = ?, updated_at = ?
        WHERE id = ?
    """, (response_note, now_str, req_id))
    conn.commit()
    conn.close()

    logger.info("Connection request #%d accepted by %s", req_id, current_user)
    flash("Connection accepted! Contact details are now available to both of you.", "success")
    return _redirect_after_connection_action(current_user, token)


@app.route("/connection_request/<int:req_id>/decline", methods=["GET", "POST"])
def decline_connection_request(req_id):
    current_user = session.get("user")
    token = request.form.get("claim_token") or request.form.get("token") or request.args.get("token") or request.args.get("claim_token") or ""

    if request.method == "GET":
        return _redirect_after_connection_action(current_user, token)

    is_authorized, req_row, target_report, error_reason = check_connection_request_authorization(req_id, current_user, token=token)

    if not is_authorized:
        if error_reason == "not_found":
            flash("Connection request not found.", "error")
        elif error_reason in ("already_accepted", "already_declined"):
            status_word = error_reason.split("_")[1]
            flash(f"This connection request has already been {status_word}.", "info")
        else:
            logger.warning("Denied unauthorized decline on connection request #%d by %s", req_id, current_user)
            flash("You do not have permission to manage this connection request.", "error")
        return _redirect_after_connection_action(current_user, token)

    now_str = datetime.now().strftime("%d %b %Y, %I:%M %p")

    conn = sqlite3.connect("lostfound.db")
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE connection_requests
        SET status = 'declined', updated_at = ?
        WHERE id = ?
    """, (now_str, req_id))
    conn.commit()
    conn.close()

    logger.info("Connection request #%d declined by %s", req_id, current_user)
    flash("Request declined.", "info")
    return _redirect_after_connection_action(current_user, token)


@app.route("/guest/connection_request/<int:req_id>/accept", methods=["GET", "POST"])
def guest_accept_connection_request(req_id):
    return accept_connection_request(req_id)


@app.route("/guest/connection_request/<int:req_id>/decline", methods=["GET", "POST"])
def guest_decline_connection_request(req_id):
    return decline_connection_request(req_id)


@app.route("/connection_request/<int:req_id>/contact", methods=["GET"])
def connection_request_contact(req_id):
    current_user = session.get("user")
    is_student = bool(current_user and current_user != "Guest")
    claimed_ids = session.get("claimed_reports", [])
    token = request.args.get("token", "").strip()

    conn = sqlite3.connect("lostfound.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT cr.id, cr.source_report_id, cr.target_report_id, cr.requester_type, cr.requester_id,
               cr.recipient_type, cr.recipient_id, cr.status, cr.message, cr.response_note, cr.contact_info,
               sr.contact, sr.email, sr.item_name, sr.item_type, sr.owner, sr.claim_token_hash, sr.claim_token_expires_at,
               tr.contact, tr.email, tr.item_name, tr.item_type, tr.owner, tr.claim_token_hash, tr.claim_token_expires_at
        FROM connection_requests cr
        JOIN reports sr ON cr.source_report_id = sr.id
        JOIN reports tr ON cr.target_report_id = tr.id
        WHERE cr.id = ?
    """, (req_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        abort(404)

    status = row[7]
    sr_id = row[1]
    tr_id = row[2]
    req_type = row[3]
    req_id_val = row[4]
    rec_type = row[5]
    rec_id_val = row[6]

    sr_contact, sr_email, sr_item_name, sr_item_type, sr_owner, sr_hash, sr_exp = row[11:18]
    tr_contact, tr_email, tr_item_name, tr_item_type, tr_owner, tr_hash, tr_exp = row[18:25]

    is_authorized = False
    role_in_request = None

    now_iso = datetime.now().isoformat()
    if is_student:
        if req_type == "student" and req_id_val == current_user:
            is_authorized = True
            role_in_request = "requester"
        elif rec_type == "student" and rec_id_val == current_user:
            is_authorized = True
            role_in_request = "recipient"

    if not is_authorized and token:
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        if sr_hash == token_hash and (not sr_exp or sr_exp >= now_iso):
            is_authorized = True
            role_in_request = "requester"
        elif tr_hash == token_hash and (not tr_exp or tr_exp >= now_iso):
            is_authorized = True
            role_in_request = "recipient"

    if not is_authorized and (sr_id in claimed_ids or tr_id in claimed_ids):
        if sr_id in claimed_ids:
            is_authorized = True
            role_in_request = "requester"
        elif tr_id in claimed_ids:
            is_authorized = True
            role_in_request = "recipient"

    if not is_authorized:
        abort(403)

    if status != "accepted":
        abort(403)

    if role_in_request == "requester":
        return jsonify({
            "status": "accepted",
            "role": "requester",
            "connection_id": req_id,
            "partner_item_name": tr_item_name,
            "partner_item_type": tr_item_type,
            "partner_contact": tr_contact,
            "partner_email": tr_email,
            "response_note": row[9]
        })
    else:
        return jsonify({
            "status": "accepted",
            "role": "recipient",
            "connection_id": req_id,
            "partner_item_name": sr_item_name,
            "partner_item_type": sr_item_type,
            "partner_contact": sr_contact,
            "partner_email": sr_email,
            "requester_extra_contact": row[10],
            "verification_clue": row[8]
        })
@app.route("/guest")
def guest():

    session["user"] = "Guest"

    return redirect("/dashboard")
def is_authorized_for_diagnostics():
    """
    Checks whether the current request is authorized to view or run SMTP diagnostics.
    Permits:
      1. Admin query token matching ADMIN_DIAGNOSTICS_TOKEN in environment.
      2. Localhost client in testing or debug mode.
      3. Authenticated student user.
    Blocks unauthenticated public callers with 403 Forbidden.
    """
    # 1. Secret token parameter if configured
    admin_token = request.args.get("token") or request.form.get("token")
    expected_token = os.environ.get("ADMIN_DIAGNOSTICS_TOKEN")
    if expected_token and admin_token and secrets.compare_digest(admin_token, expected_token):
        return True

    # 2. Localhost in debug or testing mode
    remote_ip = request.remote_addr or ""
    is_local = remote_ip in ("127.0.0.1", "::1", "localhost", "testclient")
    if is_local and (app.debug or app.testing or app.config.get("DEBUG") or app.config.get("TESTING")):
        return True

    # 3. Authenticated student user
    user = session.get("user")
    if user and user != "Guest":
        return True

    return False


@app.route("/admin/test-email", methods=["GET", "POST"])
@app.route("/test-email", methods=["GET", "POST"])
def admin_test_email():
    """
    Developer & Admin SMTP Pipeline Diagnostics Endpoint.
    Tests configuration, DNS, TCP connection, TLS/Auth, and live test email dispatch.
    Protected against unauthorized public access.
    """
    if not is_authorized_for_diagnostics():
        abort(403)

    send_test = False
    recipient = None

    if request.method == "POST":
        send_test = bool(request.form.get("send"))
        recipient = request.form.get("recipient", "").strip() or None

    report = diagnose_smtp_pipeline(send_test=send_test, recipient=recipient)

    # Support JSON API response
    if request.headers.get("Accept") == "application/json" or request.args.get("format") == "json":
        return jsonify(report)

    return render_template("email_diagnostics.html", report=report)


# ---------------- RUN APP ---------------- #

if __name__ == "__main__":

    app.run(debug=True)