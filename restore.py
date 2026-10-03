# restore.py
# Disaster Recovery & System Restore Utility for Health Archive System
# =====================================================================

import os
import sys
import json
import pathlib
import zipfile
import argparse
import logging
from cryptography.fernet import Fernet

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("health_archive.restore")

EXE_DIR = pathlib.Path(__file__).parent.resolve()
DATA_DIR = EXE_DIR / "data"
DB_PATH = DATA_DIR / "database.db"
EMPLOYEE_FILES_DIR = EXE_DIR / "employees"
KEY_FILE = DATA_DIR / "secret_key.key"

def get_encryption_key() -> bytes:
    env_key = os.environ.get("HEALTH_ARCHIVE_ENCRYPTION_KEY")
    if env_key:
        return env_key.encode("utf-8")
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    raise FileNotFoundError("Encryption secret_key.key not found in ./data/. Cannot decrypt backup.")

def decrypt_file(file_path: pathlib.Path) -> bytes:
    raw_data = file_path.read_bytes()
    if file_path.name.endswith(".enc"):
        key = get_encryption_key()
        f = Fernet(key)
        log.info(f"Decrypting encrypted backup: {file_path.name}")
        return f.decrypt(raw_data)
    return raw_data

def verify_backup(backup_path: pathlib.Path) -> bool:
    """Verifies that a backup zip archive is intact and contains valid health archive data."""
    try:
        data_bytes = decrypt_file(backup_path)
        tmp_zip = DATA_DIR / "_temp_restore.zip"
        tmp_zip.write_bytes(data_bytes)
        
        with zipfile.ZipFile(tmp_zip, 'r') as zipf:
            namelist = zipf.namelist()
            has_db = "database.db" in namelist or "database_dump.json" in namelist
            log.info(f"Archive integrity check: {len(namelist)} files contained. Has Database: {has_db}")
            
        if tmp_zip.exists():
            tmp_zip.unlink()
        return has_db
    except Exception as e:
        log.error(f"Backup verification failed for {backup_path.name}: {e}")
        return False

def restore_backup(backup_path: pathlib.Path, overwrite: bool = False) -> bool:
    """Restores database and employee files from a specified backup archive."""
    if not backup_path.exists():
        log.error(f"Backup file does not exist: {backup_path}")
        return False

    log.info(f"Starting restoration from {backup_path.name}...")
    try:
        data_bytes = decrypt_file(backup_path)
        tmp_zip = DATA_DIR / "_temp_restore.zip"
        tmp_zip.write_bytes(data_bytes)
        
        with zipfile.ZipFile(tmp_zip, 'r') as zipf:
            # 1. Restore database if present
            if "database.db" in zipf.namelist():
                if DB_PATH.exists() and not overwrite:
                    bak_existing = DB_PATH.with_suffix(f".db.bak_{int(pathlib.Path(backup_path).stat().st_mtime)}")
                    DB_PATH.rename(bak_existing)
                    log.info(f"Backed up current database to {bak_existing.name}")
                zipf.extract("database.db", path=str(DATA_DIR))
                log.info("Restored database.db successfully.")
                
            # 2. Extract employee documents
            for member in zipf.namelist():
                if member.startswith("employees/"):
                    zipf.extract(member, path=str(EXE_DIR))
            log.info("Restored employee document files successfully.")

        if tmp_zip.exists():
            tmp_zip.unlink()
            
        log.info("=" * 60)
        log.info("  DISASTER RECOVERY RESTORE COMPLETED SUCCESSFULLY")
        log.info("=" * 60)
        return True
    except Exception as e:
        log.error(f"Restore procedure failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Health Archive Backup Restore & Recovery Tool")
    parser.add_argument("--backup", type=str, help="Path to backup zip or .enc file")
    parser.add_argument("--verify", action="store_true", help="Verify backup archive integrity")
    parser.add_argument("--restore", action="store_true", help="Perform disaster recovery restore")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing database without backup")
    
    args = parser.parse_args()
    
    if not args.backup:
        backups_dir = DATA_DIR / "backups"
        if backups_dir.exists():
            backups = sorted(list(backups_dir.glob("*.zip*")), key=lambda x: x.stat().st_mtime, reverse=True)
            if backups:
                print("Available Backups:")
                for i, b in enumerate(backups[:10]):
                    print(f"  [{i+1}] {b.name} ({round(b.stat().st_size / 1024 / 1024, 2)} MB)")
                sys.exit(0)
        print("Usage: python restore.py --backup <path-to-backup> [--verify | --restore]")
        sys.exit(1)
        
    bpath = pathlib.Path(args.backup).resolve()
    if args.verify:
        if verify_backup(bpath):
            print(f"✅ Backup {bpath.name} is VALID.")
        else:
            print(f"❌ Backup {bpath.name} is INVALID or corrupted.")
            sys.exit(1)
    elif args.restore:
        if not restore_backup(bpath, overwrite=args.overwrite):
            sys.exit(1)
    else:
        print("Specify --verify or --restore")

if __name__ == "__main__":
    main()
