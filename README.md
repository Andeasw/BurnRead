# 🔥 Burn After Reading

A secure, self-destructing message system built with PHP. Features **AES-256 encryption**, **file attachments**, and a modern **Glassmorphism UI**.

## 🚀 Quick Start

1.  Upload `index.php` to your server.
2.  Create a file named `.env` in the same directory.
3.  **Copy the code below** into `.env` and configure it.
4.  Ensure the folder has write permissions (chmod 755).

## ⚙️ Configuration (.env)

```ini
# --- Security (REQUIRED) ---
# Generate a strong random string (32+ chars). 
# If changed, old messages cannot be decrypted.
ENCRYPTION_KEY="Change_This_To_A_Random_String_A1B2C3D4E5"

# --- Limits ---
# Default Expiry (Days:Hours:Minutes:Seconds)
MESSAGE_EXPIRY="30:0:0:0"

# Max allowed read count per message
MAX_READ_LIMIT="10"

# Max file upload size in MB
UPLOAD_MAX_MB="10"

# Allowed file extensions
UPLOAD_TYPES="jpg,png,gif,zip,pdf,txt,doc,docx"

# --- Site Settings ---
# Default Language ('cn' or 'en')
DEFAULT_LANG="en"

# Your Site Domain (No trailing slash)
SITE_DOMAIN="https://your-domain.com"

# Background Wallpaper URL
SITE_BACKGROUND="https://t.alcy.cc/moez"

# Site Icon Path
SITE_ICON="/favicon.jpg"
```

## 🔒 Security Note
*   All data is encrypted at rest.
*   Data is permanently deleted after the read limit or expiry time is reached.
*   **Always use HTTPS** to ensure keys are transmitted securely.

---
