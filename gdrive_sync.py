# gdrive_sync.py
# Google Drive Synchronization Manager for Health Archive System
# ================================================================

import os
import sys
import json
import time
import pathlib
import threading
import urllib.request
import urllib.parse
import logging

# Set up logging matching the main server
log = logging.getLogger("health_archive.gdrive")

# PyInstaller paths
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    EXE_DIR = pathlib.Path(sys.executable).parent.resolve()
else:
    EXE_DIR = pathlib.Path(__file__).parent.resolve()
    if (EXE_DIR / "dist").is_dir():
        EXE_DIR = EXE_DIR / "dist"

DATA_DIR    = EXE_DIR / "data"
DB_PATH     = DATA_DIR / "database.db"
AUTH_PATH   = DATA_DIR / "auth.json"
CONFIG_PATH = DATA_DIR / "gdrive_config.json"
CREDS_PATH  = DATA_DIR / "gdrive_credentials.json"

class GDriveSyncManager:
    _lock = threading.Lock()
    _is_syncing = False

    @classmethod
    def load_config(cls) -> dict:
        """Loads configuration from gdrive_config.json"""
        if not CONFIG_PATH.exists():
            return {"client_id": "", "client_secret": "", "auto_sync": False}
        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception as e:
            log.error(f"Error loading GDrive config: {e}")
            return {"client_id": "", "client_secret": "", "auto_sync": False}

    @classmethod
    def save_config(cls, config: dict):
        """Saves configuration to gdrive_config.json"""
        try:
            DATA_DIR.mkdir(exist_ok=True)
            CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
        except Exception as e:
            log.error(f"Error saving GDrive config: {e}")

    @classmethod
    def load_credentials(cls) -> dict:
        """Loads OAuth credentials from gdrive_credentials.json"""
        if not CREDS_PATH.exists():
            return {
                "access_token": "",
                "refresh_token": "",
                "expires_at": 0,
                "last_backup_time": "",
                "last_backup_status": "Disconnected"
            }
        try:
            return json.loads(CREDS_PATH.read_text(encoding="utf-8"))
        except Exception as e:
            log.error(f"Error loading GDrive credentials: {e}")
            return {
                "access_token": "",
                "refresh_token": "",
                "expires_at": 0,
                "last_backup_time": "",
                "last_backup_status": "Disconnected"
            }

    @classmethod
    def save_credentials(cls, creds: dict):
        """Saves OAuth credentials to gdrive_credentials.json"""
        try:
            DATA_DIR.mkdir(exist_ok=True)
            CREDS_PATH.write_text(json.dumps(creds, indent=2), encoding="utf-8")
        except Exception as e:
            log.error(f"Error saving GDrive credentials: {e}")

    @classmethod
    def get_auth_url(cls, client_id: str, redirect_uri: str) -> str:
        """Generates Google OAuth URL"""
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "https://www.googleapis.com/auth/drive.file",
            "access_type": "offline",
            "prompt": "consent"
        }
        return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)

    @classmethod
    def exchange_code(cls, client_id: str, client_secret: str, code: str, redirect_uri: str) -> bool:
        """Exchanges authorization code for access and refresh tokens"""
        url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code"
        }
        encoded_data = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=encoded_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                res = json.loads(resp.read().decode("utf-8"))
            
            creds = cls.load_credentials()
            creds["access_token"] = res.get("access_token")
            # Only update refresh token if Google returns it (it is only returned on the first authorization)
            if "refresh_token" in res:
                creds["refresh_token"] = res.get("refresh_token")
            creds["expires_at"] = time.time() + int(res.get("expires_in", 3600))
            creds["last_backup_status"] = "Connected"
            cls.save_credentials(creds)
            log.info("Google Drive tokens exchanged successfully.")
            return True
        except Exception as e:
            log.error(f"Failed to exchange GDrive code: {e}")
            return False

    @classmethod
    def _refresh_access_token(cls, config: dict, creds: dict) -> str:
        """Refreshes the OAuth access token if expired, returns the active token"""
        now = time.time()
        # If token is still valid for another 2 minutes, return it
        if creds.get("access_token") and creds.get("expires_at", 0) > now + 120:
            return creds["access_token"]

        if not creds.get("refresh_token"):
            raise Exception("No refresh token available. Google Drive is disconnected.")

        log.info("GDrive access token expired, refreshing...")
        url = "https://oauth2.googleapis.com/token"
        data = {
            "client_id": config.get("client_id"),
            "client_secret": config.get("client_secret"),
            "refresh_token": creds.get("refresh_token"),
            "grant_type": "refresh_token"
        }
        encoded_data = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=encoded_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                res = json.loads(resp.read().decode("utf-8"))
            
            creds["access_token"] = res.get("access_token")
            creds["expires_at"] = now + int(res.get("expires_in", 3600))
            cls.save_credentials(creds)
            log.info("GDrive access token refreshed successfully.")
            return creds["access_token"]
        except urllib.error.HTTPError as e:
            error_body = ""
            try:
                error_body = e.read().decode("utf-8")
            except Exception:
                pass
            # HTTP 400 = invalid_grant: refresh token revoked or expired
            # HTTP 401 = unauthorized: credentials wrong
            if e.code in (400, 401):
                log.error(f"GDrive refresh token is invalid or revoked (HTTP {e.code}). Clearing credentials. User must reconnect.")
                # Clear the bad tokens so auto-sync stops hammering Google
                creds["access_token"] = ""
                creds["refresh_token"] = ""
                creds["expires_at"] = 0
                creds["last_backup_status"] = "Session expired - please reconnect Google Drive"
                cls.save_credentials(creds)
                raise Exception("Google Drive session expired. Please disconnect and reconnect Google Drive in Admin settings.")
            log.error(f"Failed to refresh GDrive token (HTTP {e.code}): {error_body}")
            raise Exception(f"Failed to refresh Google Drive connection: HTTP {e.code}")
        except Exception as e:
            log.error(f"Failed to refresh GDrive token: {e}")
            raise Exception(f"Failed to refresh Google Drive connection: {e}")

    @classmethod
    def _api_request(cls, url: str, method: str = "GET", headers: dict = None, data = None):
        """Helper to make authenticated JSON API requests to Google APIs"""
        if headers is None:
            headers = {}
        
        req = urllib.request.Request(url, method=method)
        for k, v in headers.items():
            req.add_header(k, v)

        if data is not None:
            if isinstance(data, (dict, list)):
                req.data = json.dumps(data).encode("utf-8")
                if "Content-Type" not in headers:
                    req.add_header("Content-Type", "application/json; charset=UTF-8")
            else:
                req.data = data

        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    @classmethod
    def _find_or_create_folder(cls, access_token: str) -> str:
        """Finds or creates the HealthArchive_Backups folder on Google Drive"""
        headers = {"Authorization": f"Bearer {access_token}"}
        
        # 1. Search for folder
        query = "name='HealthArchive_Backups' and mimeType='application/vnd.google-apps.folder' and trashed=false"
        url = "https://www.googleapis.com/drive/v3/files?q=" + urllib.parse.quote(query)
        try:
            res = cls._api_request(url, headers=headers)
            files = res.get("files", [])
            if files:
                return files[0]["id"]
        except Exception as e:
            log.warning(f"Error searching folder on GDrive: {e}")

        # 2. Create if not found
        log.info("HealthArchive_Backups folder not found on Google Drive. Creating it...")
        create_url = "https://www.googleapis.com/drive/v3/files"
        metadata = {
            "name": "HealthArchive_Backups",
            "mimeType": "application/vnd.google-apps.folder"
        }
        res = cls._api_request(create_url, method="POST", headers=headers, data=metadata)
        return res["id"]

    @classmethod
    def _find_file_in_folder(cls, access_token: str, filename: str, folder_id: str) -> str:
        """Finds a file by name inside a specific folder, returning its ID or None"""
        headers = {"Authorization": f"Bearer {access_token}"}
        query = f"name='{filename}' and '{folder_id}' in parents and trashed=false"
        url = "https://www.googleapis.com/drive/v3/files?q=" + urllib.parse.quote(query)
        try:
            res = cls._api_request(url, headers=headers)
            files = res.get("files", [])
            if files:
                return files[0]["id"]
        except Exception as e:
            log.warning(f"Error searching file '{filename}' on GDrive: {e}")
        return None

    @classmethod
    def _upload_or_update_file(cls, access_token: str, folder_id: str, file_path: pathlib.Path, remote_name: str, mime_type: str):
        """Uploads a file to Google Drive using multipart upload. Updates if exists."""
        if not file_path.exists():
            log.warning(f"File {file_path} does not exist, skipping GDrive upload.")
            return

        file_bytes = file_path.read_bytes()
        file_id = cls._find_file_in_folder(access_token, remote_name, folder_id)

        boundary = "gdrive_upload_boundary_777777777"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": f"multipart/related; boundary={boundary}"
        }

        metadata = {"name": remote_name}
        if not file_id:
            # Create a new file
            url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"
            method = "POST"
            metadata["parents"] = [folder_id]
            log.info(f"Uploading new file '{remote_name}' to GDrive...")
        else:
            # Update existing file (native Google Drive version control)
            url = f"https://www.googleapis.com/upload/drive/v3/files/{file_id}?uploadType=multipart"
            method = "PATCH"
            log.info(f"Updating existing file '{remote_name}' (ID: {file_id}) on GDrive...")

        # Construct multipart body
        body_parts = [
            f"--{boundary}\r\n".encode("utf-8"),
            "Content-Type: application/json; charset=UTF-8\r\n\r\n".encode("utf-8"),
            (json.dumps(metadata) + "\r\n").encode("utf-8"),
            f"--{boundary}\r\n".encode("utf-8"),
            f"Content-Type: {mime_type}\r\n\r\n".encode("utf-8"),
            file_bytes,
            f"\r\n--{boundary}--\r\n".encode("utf-8")
        ]
        body = b"".join(body_parts)

        cls._api_request(url, method=method, headers=headers, data=body)
        log.info(f"File '{remote_name}' sync complete.")

    @classmethod
    def sync_backup(cls) -> bool:
        """
        Executes backup synchronization:
        Refreshes tokens, locates folder, and uploads database.db and auth.json.
        This method is thread-safe and updates credential statuses on success or failure.
        """
        with cls._lock:
            if cls._is_syncing:
                log.warning("Sync already in progress. Skipping duplicate call.")
                return False
            cls._is_syncing = True

        try:
            config = cls.load_config()
            creds = cls.load_credentials()

            if not config.get("client_id") or not config.get("client_secret"):
                raise Exception("Google Client ID and Secret are not configured.")
            if not creds.get("refresh_token"):
                raise Exception("Google Drive is not connected (no refresh token).")

            # 1. Get active token
            access_token = cls._refresh_access_token(config, creds)

            # 2. Get folder ID
            folder_id = cls._find_or_create_folder(access_token)

            # 3. Upload database.db
            cls._upload_or_update_file(
                access_token=access_token,
                folder_id=folder_id,
                file_path=DB_PATH,
                remote_name="health_archive_database.db",
                mime_type="application/x-sqlite3"
            )

            # 4. Upload auth.json (to preserve user credentials/password hashes)
            cls._upload_or_update_file(
                access_token=access_token,
                folder_id=folder_id,
                file_path=AUTH_PATH,
                remote_name="health_archive_auth.json",
                mime_type="application/json; charset=UTF-8"
            )

            # Save success state
            creds = cls.load_credentials() # reload in case modified in between
            creds["last_backup_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
            creds["last_backup_status"] = "Success"
            cls.save_credentials(creds)
            log.info("Google Drive sync backup completed successfully.")
            return True

        except Exception as e:
            log.error(f"Google Drive sync failed: {e}")
            creds = cls.load_credentials()
            creds["last_backup_status"] = f"Failed: {str(e)}"
            cls.save_credentials(creds)
            return False

        finally:
            with cls._lock:
                cls._is_syncing = False

    @classmethod
    def start_async_sync(cls):
        """Starts the sync_backup process inside a background thread to prevent blocking Flask"""
        thread = threading.Thread(target=cls.sync_backup, daemon=True)
        thread.start()
        return thread
