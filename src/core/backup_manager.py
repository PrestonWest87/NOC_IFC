"""Encrypted, complete SQLite backups and maintenance-window restore support."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import struct
import tempfile
import threading
import uuid
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.config import settings
from src.core.paths import application_data_dir, ml_model_path, sqlite_database_path

logger = logging.getLogger(__name__)

BACKUP_FORMAT_VERSION = 1
BACKUP_MAGIC = b"NOCIFCBK"
CHUNK_SIZE = 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
_HEADER_LENGTH = struct.Struct(">I")
_RECORD_HEADER = struct.Struct(">BI")
_DATA_RECORD = 1
_FINAL_RECORD = 2
_BACKUP_FILENAME = re.compile(
    r"^noc-ifc-(manual|pre-restore|scheduled)-(\d{8}T\d{6}Z)-([0-9a-f]{32})\.nocbackup$"
)
_STAGED_FILENAME = re.compile(r"^stage-([0-9a-f]{32})\.nocbackup$")
_KEY_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_LOCK = threading.RLock()


class BackupError(ValueError):
    """A backup is invalid, unavailable, or cannot be safely created/restored."""


def backup_directory() -> Path:
    return application_data_dir() / "backups"


def _max_bytes(value: int | None = None) -> int:
    raw = value if value is not None else settings.backup_max_bytes
    if isinstance(raw, bool):
        raise BackupError("BACKUP_MAX_BYTES must be a positive integer.")
    try:
        result = int(raw)
    except (TypeError, ValueError) as exc:
        raise BackupError("BACKUP_MAX_BYTES must be a positive integer.") from exc
    if str(raw).strip() != str(result):
        raise BackupError("BACKUP_MAX_BYTES must be a positive integer.")
    if result <= 0:
        raise BackupError("BACKUP_MAX_BYTES must be a positive integer.")
    return result


def _encryption_keys() -> tuple[dict[str, bytes], str]:
    raw = str(settings.backup_encryption_keys or "").strip()
    active_id = str(settings.backup_encryption_active_key_id or "").strip()
    if not raw:
        raise BackupError("Encrypted backups are unavailable until BACKUP_ENCRYPTION_KEYS is configured.")
    if not _KEY_ID.fullmatch(active_id):
        raise BackupError("BACKUP_ENCRYPTION_ACTIVE_KEY_ID must be 1-64 letters, numbers, dots, underscores, or hyphens.")
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise BackupError("BACKUP_ENCRYPTION_KEYS must be a JSON object of key IDs and 64-character hex keys.") from exc
    if not isinstance(parsed, dict) or not parsed:
        raise BackupError("BACKUP_ENCRYPTION_KEYS must be a non-empty JSON object.")
    keys: dict[str, bytes] = {}
    for key_id, key_hex in parsed.items():
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise BackupError("Backup encryption key IDs may contain only letters, numbers, dots, underscores, and hyphens.")
        if not isinstance(key_hex, str):
            raise BackupError(f"Backup encryption key {key_id!r} must be a 64-character hex string.")
        if re.fullmatch(r"[0-9a-fA-F]{64}", key_hex) is None:
            raise BackupError(f"Backup encryption key {key_id!r} must be a 64-character hex string.")
        try:
            key = bytes.fromhex(key_hex)
        except ValueError as exc:
            raise BackupError(f"Backup encryption key {key_id!r} is not valid hexadecimal.") from exc
        if len(key) != 32:
            raise BackupError(f"Backup encryption key {key_id!r} must decode to exactly 32 bytes.")
        keys[key_id] = key
    if active_id not in keys:
        raise BackupError("The active backup encryption key ID is not present in BACKUP_ENCRYPTION_KEYS.")
    return keys, active_id


def _backup_root(path: str | Path | None = None) -> Path:
    root = Path(path) if path is not None else backup_directory()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    return root.resolve()


def encryption_configured() -> bool:
    try:
        _encryption_keys()
        return True
    except BackupError:
        return False


@contextmanager
def _backup_lock(root: Path):
    lock_path = root / ".backup.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        with os.fdopen(descriptor, "r+") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                with _LOCK:
                    yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _database_metadata(path: Path) -> dict:
    connection = sqlite3.connect(str(path), timeout=60)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if not integrity or integrity[0] != "ok":
            raise BackupError("The SQLite database failed PRAGMA integrity_check.")
        tables = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )]
        return {"integrity": "ok", "tables": tables, "table_count": len(tables)}
    except sqlite3.DatabaseError as exc:
        raise BackupError("The SQLite database could not be read or verified.") from exc
    finally:
        connection.close()


def _sqlite_snapshot(source_path: Path, destination_path: Path) -> dict:
    if not source_path.is_file():
        raise BackupError(f"SQLite database file does not exist: {source_path}")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    source = sqlite3.connect(str(source_path), timeout=60)
    destination = sqlite3.connect(str(destination_path), timeout=60)
    try:
        source.execute("PRAGMA busy_timeout=60000")
        source.backup(destination, pages=256, sleep=0.05)
        destination.commit()
    except sqlite3.DatabaseError as exc:
        raise BackupError("SQLite could not create a consistent online database snapshot.") from exc
    finally:
        destination.close()
        source.close()
    os.chmod(destination_path, 0o600)
    metadata = _database_metadata(destination_path)
    metadata.update({"size_bytes": destination_path.stat().st_size, "sha256": _sha256_file(destination_path)})
    return metadata


def _record_aad(header_frame: bytes, record_type: int, index: int) -> bytes:
    return header_frame + bytes([record_type]) + index.to_bytes(8, "big")


def _nonce(prefix: bytes, index: int) -> bytes:
    if index >= 2**32:
        raise BackupError("The backup exceeds the supported encrypted chunk count.")
    return prefix + index.to_bytes(4, "big")


def _read_exact(stream, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        data = stream.read(remaining)
        if not data:
            raise BackupError("The encrypted backup is truncated.")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def _encrypt_file(source_path: Path, destination_path: Path, max_bytes: int) -> int:
    keys, active_id = _encryption_keys()
    key = keys[active_id]
    nonce_prefix = secrets.token_bytes(8)
    header = {
        "format_version": BACKUP_FORMAT_VERSION,
        "algorithm": "AES-256-GCM",
        "key_id": active_id,
        "nonce_prefix": nonce_prefix.hex(),
        "chunk_size": CHUNK_SIZE,
    }
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    header_frame = BACKUP_MAGIC + _HEADER_LENGTH.pack(len(header_bytes)) + header_bytes
    aes = AESGCM(key)
    total_plaintext = 0
    chunk_index = 0
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with source_path.open("rb") as source, destination_path.open("xb") as encrypted:
            os.chmod(destination_path, 0o600)
            encrypted.write(header_frame)
            while True:
                block = source.read(CHUNK_SIZE)
                if not block:
                    break
                total_plaintext += len(block)
                if total_plaintext > max_bytes:
                    raise BackupError("The unencrypted backup archive exceeds BACKUP_MAX_BYTES.")
                ciphertext = aes.encrypt(
                    _nonce(nonce_prefix, chunk_index), block,
                    _record_aad(header_frame, _DATA_RECORD, chunk_index),
                )
                encrypted.write(_RECORD_HEADER.pack(_DATA_RECORD, len(ciphertext)))
                encrypted.write(ciphertext)
                chunk_index += 1
                if encrypted.tell() > max_bytes:
                    raise BackupError("The encrypted backup exceeds BACKUP_MAX_BYTES.")
            final_tag = aes.encrypt(
                _nonce(nonce_prefix, chunk_index), b"",
                _record_aad(header_frame, _FINAL_RECORD, chunk_index),
            )
            encrypted.write(_RECORD_HEADER.pack(_FINAL_RECORD, len(final_tag)))
            encrypted.write(final_tag)
            encrypted.flush()
            os.fsync(encrypted.fileno())
            final_size = encrypted.tell()
        if final_size > max_bytes:
            raise BackupError("The encrypted backup exceeds BACKUP_MAX_BYTES.")
        return final_size
    except Exception:
        destination_path.unlink(missing_ok=True)
        raise


def _decrypt_file(source_path: Path, destination_path: Path, max_bytes: int) -> dict:
    try:
        encrypted_size = source_path.stat().st_size
    except OSError as exc:
        raise BackupError("The encrypted backup file could not be read.") from exc
    if encrypted_size <= 0 or encrypted_size > max_bytes:
        raise BackupError("The encrypted backup is empty or exceeds BACKUP_MAX_BYTES.")
    keys, _active_id = _encryption_keys()
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with source_path.open("rb") as source:
            if _read_exact(source, len(BACKUP_MAGIC)) != BACKUP_MAGIC:
                raise BackupError("This is not a NOC Fusion encrypted backup.")
            header_size_bytes = _read_exact(source, _HEADER_LENGTH.size)
            header_size = _HEADER_LENGTH.unpack(header_size_bytes)[0]
            if not 1 <= header_size <= MAX_HEADER_BYTES:
                raise BackupError("The encrypted backup header is invalid.")
            header_bytes = _read_exact(source, header_size)
            header_frame = BACKUP_MAGIC + header_size_bytes + header_bytes
            try:
                header = json.loads(header_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BackupError("The encrypted backup header is invalid.") from exc
            if (
                not isinstance(header, dict)
                or type(header.get("format_version")) is not int
                or header.get("format_version") != BACKUP_FORMAT_VERSION
            ):
                raise BackupError("This encrypted backup format version is not supported.")
            if header.get("algorithm") != "AES-256-GCM":
                raise BackupError("The encrypted backup algorithm is not supported.")
            key_id = header.get("key_id")
            if not isinstance(key_id, str) or key_id not in keys:
                raise BackupError("The encryption key required by this backup is not configured.")
            nonce_prefix_hex = header.get("nonce_prefix")
            if not isinstance(nonce_prefix_hex, str):
                raise BackupError("The encrypted backup nonce is invalid.")
            try:
                prefix = bytes.fromhex(nonce_prefix_hex)
            except ValueError as exc:
                raise BackupError("The encrypted backup nonce is invalid.") from exc
            chunk_size = header.get("chunk_size")
            if len(prefix) != 8 or isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
                raise BackupError("The encrypted backup header is invalid.")
            if not 64 * 1024 <= chunk_size <= 8 * 1024 * 1024:
                raise BackupError("The encrypted backup chunk size is not supported.")

            aes = AESGCM(keys[key_id])
            chunk_index = 0
            total_plaintext = 0
            with destination_path.open("xb") as destination:
                os.chmod(destination_path, 0o600)
                while True:
                    record_header = _read_exact(source, _RECORD_HEADER.size)
                    record_type, record_size = _RECORD_HEADER.unpack(record_header)
                    if record_type == _DATA_RECORD:
                        if not 16 < record_size <= chunk_size + 16:
                            raise BackupError("The encrypted backup contains an invalid data chunk.")
                    elif record_type == _FINAL_RECORD:
                        if record_size != 16:
                            raise BackupError("The encrypted backup final marker is invalid.")
                    else:
                        raise BackupError("The encrypted backup contains an unknown record type.")
                    ciphertext = _read_exact(source, record_size)
                    if record_type == _DATA_RECORD:
                        try:
                            plaintext = aes.decrypt(
                                _nonce(prefix, chunk_index), ciphertext,
                                _record_aad(header_frame, _DATA_RECORD, chunk_index),
                            )
                        except InvalidTag as exc:
                            raise BackupError("Backup authentication failed; the file or encryption key is invalid.") from exc
                        total_plaintext += len(plaintext)
                        if total_plaintext > max_bytes:
                            raise BackupError("The decrypted backup exceeds BACKUP_MAX_BYTES.")
                        destination.write(plaintext)
                        chunk_index += 1
                        continue
                    if record_type == _FINAL_RECORD:
                        try:
                            aes.decrypt(
                                _nonce(prefix, chunk_index), ciphertext,
                                _record_aad(header_frame, _FINAL_RECORD, chunk_index),
                            )
                        except InvalidTag as exc:
                            raise BackupError("Backup authentication failed; the file or encryption key is invalid.") from exc
                        if source.read(1):
                            raise BackupError("The encrypted backup has unexpected trailing data.")
                        destination.flush()
                        os.fsync(destination.fileno())
                        break
        return {"key_id": key_id, "encrypted_size_bytes": encrypted_size}
    except Exception:
        destination_path.unlink(missing_ok=True)
        raise


def _manifest_summary(manifest: dict) -> dict:
    database = manifest["database"]
    model = manifest.get("model")
    category = manifest.get("backup_category")
    if category is None and manifest.get("reason") == "pre-restore safety snapshot":
        category = "pre-restore"
    return {
        "format_version": manifest["format_version"],
        "backup_kind": manifest["backup_kind"],
        "category": category or manifest["backup_kind"],
        "created_at": manifest["created_at"],
        "database_size_bytes": database["size_bytes"],
        "table_count": database["table_count"],
        "model_included": model is not None,
        "reason": manifest.get("reason"),
    }


@contextmanager
def _extract_and_validate(package_path: Path, workspace: Path, max_bytes: int):
    archive_path = workspace / "payload.zip"
    _decrypt_file(package_path, archive_path, max_bytes)
    database_path = workspace / "database.sqlite"
    model_path = workspace / "ml_model.pkl"
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            members = archive.infolist()
            names = [item.filename for item in members]
            if len(names) != len(set(names)) or "manifest.json" not in names:
                raise BackupError("The backup archive has duplicate entries or no manifest.")
            if any(
                item.is_dir()
                or item.filename.startswith(("/", "\\"))
                or ".." in Path(item.filename).parts
                or item.flag_bits & 0x1
                or item.compress_type != zipfile.ZIP_STORED
                or item.compress_size != item.file_size
                for item in members
            ):
                raise BackupError("The backup archive contains an unsafe or unsupported entry.")
            manifest_info = archive.getinfo("manifest.json")
            if manifest_info.file_size > MAX_MANIFEST_BYTES:
                raise BackupError("The backup manifest is too large.")
            try:
                manifest = json.loads(archive.read(manifest_info).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
                raise BackupError("The backup manifest is corrupt.") from exc
            _validate_manifest(manifest, names, max_bytes)

            database_info = archive.getinfo("database.sqlite")
            _copy_archive_entry(
                archive, database_info, database_path,
                manifest["database"]["size_bytes"], manifest["database"]["sha256"], max_bytes,
            )
            model = manifest.get("model")
            if model is not None:
                model_info = archive.getinfo("model/ml_model.pkl")
                _copy_archive_entry(
                    archive, model_info, model_path, model["size_bytes"], model["sha256"], max_bytes,
                )
            db_metadata = _database_metadata(database_path)
            if db_metadata["tables"] != manifest["database"]["tables"]:
                raise BackupError("The SQLite table inventory does not match the signed backup manifest.")
        archive_path.unlink(missing_ok=True)
        yield manifest, database_path, model_path if manifest.get("model") is not None else None
    except zipfile.BadZipFile as exc:
        raise BackupError("The decrypted backup archive is corrupt.") from exc


def _validate_manifest(manifest, member_names: list[str], max_bytes: int) -> None:
    if not isinstance(manifest, dict) or manifest.get("format_version") != BACKUP_FORMAT_VERSION:
        raise BackupError("This backup manifest version is not supported.")
    if manifest.get("backup_kind") not in {"manual", "scheduled"}:
        raise BackupError("The backup kind is invalid.")
    try:
        datetime.fromisoformat(str(manifest["created_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError) as exc:
        raise BackupError("The backup manifest creation timestamp is invalid.") from exc
    database = manifest.get("database")
    if not isinstance(database, dict) or database.get("file") != "database.sqlite":
        raise BackupError("The backup manifest has no SQLite database payload.")
    if not _valid_file_metadata(database, max_bytes):
        raise BackupError("The backup manifest database checksum or size is invalid.")
    tables = database.get("tables")
    if not isinstance(tables, list) or not all(isinstance(item, str) for item in tables):
        raise BackupError("The backup manifest table inventory is invalid.")
    table_count = database.get("table_count")
    if isinstance(table_count, bool) or not isinstance(table_count, int) or table_count != len(tables):
        raise BackupError("The backup manifest table count is invalid.")
    category = manifest.get("backup_category", manifest["backup_kind"])
    if category not in {"manual", "pre-restore", "scheduled"}:
        raise BackupError("The backup manifest category is invalid.")
    if category == "pre-restore" and manifest["backup_kind"] != "manual":
        raise BackupError("A pre-restore safety package must have manual retention.")
    model = manifest.get("model")
    expected_names = {"manifest.json", "database.sqlite"}
    if model is not None:
        if not isinstance(model, dict) or model.get("file") != "model/ml_model.pkl" or not _valid_file_metadata(model, max_bytes):
            raise BackupError("The backup manifest model payload is invalid.")
        expected_names.add("model/ml_model.pkl")
    payload_size = database["size_bytes"] + (model["size_bytes"] if model is not None else 0)
    if payload_size > max_bytes:
        raise BackupError("The backup payload exceeds BACKUP_MAX_BYTES.")
    if set(member_names) != expected_names:
        raise BackupError("The backup archive contains missing or unexpected files.")


def _valid_file_metadata(metadata: dict, max_bytes: int) -> bool:
    size = metadata.get("size_bytes")
    digest = metadata.get("sha256")
    return (
        isinstance(size, int) and not isinstance(size, bool) and 0 < size <= max_bytes
        and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
    )


def _copy_archive_entry(archive, info, destination: Path, expected_size: int, expected_digest: str, max_bytes: int) -> None:
    if info.file_size != expected_size or expected_size > max_bytes:
        raise BackupError(f"The backup payload size is invalid for {info.filename}.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    with archive.open(info, "r") as source, destination.open("xb") as output:
        os.chmod(destination, 0o600)
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            if size > expected_size or size > max_bytes:
                raise BackupError(f"The backup payload size is invalid for {info.filename}.")
            digest.update(block)
            output.write(block)
    if size != expected_size or digest.hexdigest() != expected_digest:
        destination.unlink(missing_ok=True)
        raise BackupError(f"The backup checksum does not match for {info.filename}.")


def validate_backup(package_path: str | Path, *, max_bytes: int | None = None) -> dict:
    """Authenticate, unpack, checksum, and integrity-check an encrypted backup."""
    package = Path(package_path)
    limit = _max_bytes(max_bytes)
    with tempfile.TemporaryDirectory(prefix="noc-ifc-validate-") as work:
        workspace = Path(work)
        with _extract_and_validate(package, workspace, limit) as (manifest, _db_path, _model_path):
            return {
                "manifest": manifest,
                "summary": _manifest_summary(manifest),
                "encrypted_size_bytes": package.stat().st_size,
            }


def _backup_filename(kind: str, created_at: datetime, backup_id: str, *, category: str | None = None) -> str:
    timestamp = created_at.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"noc-ifc-{category or kind}-{timestamp}-{backup_id}.nocbackup"


def _file_record(path: Path, kind: str, created_at: datetime, summary: dict) -> dict:
    return {
        "id": path.name,
        "filename": path.name,
        "kind": kind,
        "created_at": created_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "size_bytes": path.stat().st_size,
        **summary,
    }


def create_backup(
    kind: str = "manual",
    *,
    reason: str | None = None,
    created_by: str | None = None,
    database_path: str | Path | None = None,
    model_path: str | Path | None = None,
    backup_dir: str | Path | None = None,
    max_bytes: int | None = None,
) -> dict:
    """Create a consistent full SQLite snapshot, encrypt it, and apply retention."""
    if kind not in {"manual", "scheduled"}:
        raise BackupError("Backup kind must be 'manual' or 'scheduled'.")
    limit = _max_bytes(max_bytes)
    _encryption_keys()  # Fail before doing potentially expensive SQLite work.
    source_path = Path(database_path) if database_path is not None else sqlite_database_path()
    if source_path is None:
        raise BackupError("A persistent SQLite database file is required for full backups.")
    source_path = source_path.resolve()
    current_model = Path(model_path) if model_path is not None else ml_model_path()
    root = _backup_root(backup_dir)
    created_at = datetime.now(timezone.utc).replace(microsecond=0)
    backup_id = uuid.uuid4().hex
    category = "pre-restore" if reason == "pre-restore safety snapshot" else kind
    filename = _backup_filename(kind, created_at, backup_id, category=category)
    final_path = root / filename

    with _backup_lock(root), tempfile.TemporaryDirectory(prefix="noc-ifc-backup-") as work:
        workspace = Path(work)
        snapshot_path = workspace / "database.sqlite"
        database_info = _sqlite_snapshot(source_path, snapshot_path)
        model_info = None
        included_model = None
        if current_model.exists():
            if not current_model.is_file() or current_model.is_symlink():
                raise BackupError("The trained model artifact is not a regular file.")
            included_model = workspace / "ml_model.pkl"
            shutil.copyfile(current_model, included_model)
            os.chmod(included_model, 0o600)
            model_info = {
                "file": "model/ml_model.pkl",
                "size_bytes": included_model.stat().st_size,
                "sha256": _sha256_file(included_model),
            }
        database_info.update({"file": "database.sqlite"})
        manifest = {
            "format_version": BACKUP_FORMAT_VERSION,
            "created_at": created_at.isoformat().replace("+00:00", "Z"),
            "backup_kind": kind,
            "backup_category": category,
            "reason": str(reason or "")[:200] or None,
            "created_by": str(created_by or "")[:128] or None,
            "database": database_info,
            "model": model_info,
        }
        archive_path = workspace / "payload.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            archive.write(snapshot_path, "database.sqlite")
            if included_model is not None:
                archive.write(included_model, "model/ml_model.pkl")
            info = zipfile.ZipInfo("manifest.json")
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o600 << 16
            archive.writestr(info, json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        snapshot_path.unlink(missing_ok=True)
        if included_model is not None:
            included_model.unlink(missing_ok=True)
        if archive_path.stat().st_size > limit:
            raise BackupError("The full backup archive exceeds BACKUP_MAX_BYTES.")

        partial_path = root / f".{filename}.{uuid.uuid4().hex}.part"
        try:
            encrypted_size = _encrypt_file(archive_path, partial_path, limit)
            os.replace(partial_path, final_path)
            _fsync_directory(root)
        finally:
            partial_path.unlink(missing_ok=True)

        if kind == "scheduled":
            _prune_scheduled(root, keep=3)
    return _file_record(final_path, category, created_at, {
        "table_count": database_info["table_count"],
        "model_included": model_info is not None,
        "reason": manifest["reason"],
    } | {"encrypted_size_bytes": encrypted_size})


def _prune_scheduled(root: Path, keep: int) -> None:
    scheduled = []
    for path in root.glob("noc-ifc-scheduled-*.nocbackup"):
        match = _BACKUP_FILENAME.fullmatch(path.name)
        if match and path.is_file() and not path.is_symlink():
            scheduled.append(path)
    scheduled.sort(key=lambda item: item.stat().st_mtime_ns, reverse=True)
    for path in scheduled[keep:]:
        path.unlink(missing_ok=True)


def _fsync_directory(directory: Path) -> None:
    try:
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        logger.debug("Could not fsync backup directory %s", directory, exc_info=True)


def list_backups(*, backup_dir: str | Path | None = None) -> list[dict]:
    root = _backup_root(backup_dir)
    records = []
    for path in root.glob("noc-ifc-*.nocbackup"):
        match = _BACKUP_FILENAME.fullmatch(path.name)
        if not match or not path.is_file() or path.is_symlink():
            continue
        kind, timestamp, _backup_id = match.groups()
        created_at = datetime.strptime(timestamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        records.append({
            "id": path.name,
            "filename": path.name,
            "kind": kind,
            "created_at": created_at.isoformat().replace("+00:00", "Z"),
            "size_bytes": path.stat().st_size,
        })
    return sorted(records, key=lambda item: item["created_at"], reverse=True)


def get_backup_path(backup_id: str, *, backup_dir: str | Path | None = None) -> Path:
    if not isinstance(backup_id, str) or not _BACKUP_FILENAME.fullmatch(backup_id):
        raise BackupError("Backup not found.")
    path = _backup_root(backup_dir) / backup_id
    if not path.is_file() or path.is_symlink():
        raise BackupError("Backup not found.")
    return path


def relabel_legacy_pre_restore_backup(backup_id: str, *, backup_dir: str | Path | None = None) -> str:
    """Rename an older manual-named safety package after checking its encrypted manifest."""
    path = get_backup_path(backup_id, backup_dir=backup_dir)
    match = _BACKUP_FILENAME.fullmatch(path.name)
    if not match:
        raise BackupError("Backup not found.")
    category, timestamp, backup_id_suffix = match.groups()
    if category == "pre-restore":
        return path.name
    if category != "manual":
        raise BackupError("Only a legacy manual-named safety backup can be relabeled.")
    manifest = validate_backup(path)["manifest"]
    if manifest.get("reason") != "pre-restore safety snapshot":
        raise BackupError("Backup is not a pre-restore safety snapshot.")
    created_at = datetime.strptime(timestamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    new_name = _backup_filename("manual", created_at, backup_id_suffix, category="pre-restore")
    destination = path.with_name(new_name)
    if destination.exists():
        raise BackupError("The pre-restore safety backup label already exists.")
    os.replace(path, destination)
    _fsync_directory(destination.parent)
    return destination.name


def delete_backup(backup_id: str, *, backup_dir: str | Path | None = None) -> None:
    path = get_backup_path(backup_id, backup_dir=backup_dir)
    match = _BACKUP_FILENAME.fullmatch(path.name)
    if not match or match.group(1) not in {"manual", "pre-restore"}:
        if match and match.group(1) == "scheduled":
            raise BackupError("Scheduled backups are managed by the three-backup retention policy.")
        raise BackupError("Backup not found.")
    path.unlink()


def stage_uploaded_backup(source, *, backup_dir: str | Path | None = None, max_bytes: int | None = None) -> dict:
    """Persist an uploaded encrypted package only after full authentication/validation."""
    limit = _max_bytes(max_bytes)
    root = _backup_root(backup_dir)
    staged_dir = root / "staged"
    staged_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(staged_dir, 0o700)
    temporary_path = staged_dir / f".upload-{uuid.uuid4().hex}.part"
    size = 0
    try:
        with temporary_path.open("xb") as destination:
            os.chmod(temporary_path, 0o600)
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > limit:
                    raise BackupError("The uploaded backup exceeds BACKUP_MAX_BYTES.")
                destination.write(block)
            destination.flush()
            os.fsync(destination.fileno())
        if size == 0:
            raise BackupError("The uploaded backup is empty.")
        validation = validate_backup(temporary_path, max_bytes=limit)
        stage_id = uuid.uuid4().hex
        stage_name = f"stage-{stage_id}.nocbackup"
        staged_path = staged_dir / stage_name
        os.replace(temporary_path, staged_path)
        _fsync_directory(staged_dir)
        return {
            "stage_id": stage_name,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "size_bytes": size,
            **validation["summary"],
        }
    finally:
        temporary_path.unlink(missing_ok=True)


def list_staged_backups(*, backup_dir: str | Path | None = None) -> list[dict]:
    staged_dir = _backup_root(backup_dir) / "staged"
    staged_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(staged_dir, 0o700)
    records = []
    for path in staged_dir.glob("stage-*.nocbackup"):
        if _STAGED_FILENAME.fullmatch(path.name) and path.is_file() and not path.is_symlink():
            records.append({
                "stage_id": path.name,
                "created_at": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat().replace("+00:00", "Z"),
                "size_bytes": path.stat().st_size,
            })
    return sorted(records, key=lambda item: item["created_at"], reverse=True)


def delete_staged_backup(stage_id: str, *, backup_dir: str | Path | None = None) -> None:
    get_staged_backup_path(stage_id, backup_dir=backup_dir).unlink()


def clear_staged_backups(*, backup_dir: str | Path | None = None) -> int:
    """Remove every staged restore package after a successful restore."""
    staged_dir = _backup_root(backup_dir) / "staged"
    if not staged_dir.is_dir() or staged_dir.is_symlink():
        return 0
    removed = 0
    for path in staged_dir.glob("stage-*.nocbackup"):
        if _STAGED_FILENAME.fullmatch(path.name) and path.is_file() and not path.is_symlink():
            path.unlink()
            removed += 1
    if removed:
        _fsync_directory(staged_dir)
    return removed


def get_staged_backup_path(stage_id: str, *, backup_dir: str | Path | None = None) -> Path:
    if not isinstance(stage_id, str) or not _STAGED_FILENAME.fullmatch(stage_id):
        raise BackupError("Staged backup not found.")
    path = _backup_root(backup_dir) / "staged" / stage_id
    if not path.is_file() or path.is_symlink():
        raise BackupError("Staged backup not found.")
    return path


def _upgrade_database(path: Path) -> None:
    from sqlalchemy import create_engine
    from sqlalchemy.engine import URL
    from sqlalchemy.pool import NullPool

    from src.core.migration_runner import run_migrations

    engine = create_engine(
        URL.create("sqlite", database=str(path)),
        poolclass=NullPool,
        connect_args={"check_same_thread": False, "timeout": 60},
    )
    try:
        run_migrations(engine)
    finally:
        engine.dispose()


def _invalidate_restored_credentials(path: Path) -> dict:
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ", timespec="microseconds")
    connection = sqlite3.connect(str(path), timeout=60)
    try:
        cursor = connection.execute("UPDATE users SET session_token = NULL WHERE session_token IS NOT NULL")
        legacy_sessions = cursor.rowcount
        cursor = connection.execute("DELETE FROM user_sessions")
        sessions = cursor.rowcount
        cursor = connection.execute(
            "UPDATE registration_invites SET revoked_at = ? "
            "WHERE revoked_at IS NULL AND used_at IS NULL", (now,),
        )
        invites = cursor.rowcount
        cursor = connection.execute(
            "UPDATE password_reset_tokens SET used_at = ? WHERE used_at IS NULL", (now,),
        )
        reset_tokens = cursor.rowcount
        cursor = connection.execute(
            "UPDATE email_change_requests SET status = 'invalidated', "
            "verification_token_hash = NULL, verification_expires_at = NULL "
            "WHERE status = 'pending_verification' AND verification_token_hash IS NOT NULL"
        )
        email_tokens = cursor.rowcount
        connection.commit()
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if not integrity or integrity[0] != "ok":
            raise BackupError("The restored SQLite database failed integrity_check after credential invalidation.")
        return {
            "legacy_sessions": max(legacy_sessions, 0),
            "sessions": max(sessions, 0),
            "registration_invites": max(invites, 0),
            "password_reset_tokens": max(reset_tokens, 0),
            "recovery_email_tokens": max(email_tokens, 0),
        }
    except sqlite3.DatabaseError as exc:
        connection.rollback()
        raise BackupError("The restored database could not invalidate outstanding credentials.") from exc
    finally:
        connection.close()


def _copy_to_temporary_file(source: Path, destination_directory: Path, final_name: str) -> Path:
    destination_directory.mkdir(parents=True, exist_ok=True)
    temporary_path = destination_directory / f".{final_name}.{uuid.uuid4().hex}.restore-tmp"
    try:
        with source.open("rb") as src, temporary_path.open("xb") as dst:
            os.chmod(temporary_path, 0o600)
            shutil.copyfileobj(src, dst, length=1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        return temporary_path
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def _restore_sidecars(database_path: Path) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        Path(f"{database_path}{suffix}").unlink(missing_ok=True)


def restore_backup(
    package_path: str | Path,
    *,
    maintenance_confirmed: bool = False,
    database_path: str | Path | None = None,
    model_path: str | Path | None = None,
    backup_dir: str | Path | None = None,
    max_bytes: int | None = None,
) -> dict:
    """Restore a validated backup. Call only after stopping API, worker, and webhook."""
    if not maintenance_confirmed:
        raise BackupError("Pass maintenance_confirmed=True only after stopping API, worker, and webhook services.")
    limit = _max_bytes(max_bytes)
    package = Path(package_path).resolve()
    live_database = Path(database_path) if database_path is not None else sqlite_database_path()
    if live_database is None:
        raise BackupError("A persistent SQLite database file is required for restore.")
    live_database = live_database.resolve()
    live_model = Path(model_path) if model_path is not None else ml_model_path()
    root = _backup_root(backup_dir)
    live_database.parent.mkdir(parents=True, exist_ok=True)
    live_model.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="noc-ifc-restore-") as work:
        workspace = Path(work)
        with _extract_and_validate(package, workspace, limit) as (manifest, restored_db, restored_model):
            _upgrade_database(restored_db)
            _database_metadata(restored_db)
            invalidated = _invalidate_restored_credentials(restored_db)
            _database_metadata(restored_db)

            safety_backup = None
            current_db_snapshot = workspace / "current.sqlite"
            old_model = workspace / "current-model.pkl"
            had_current_db = live_database.is_file()
            had_current_model = live_model.is_file()
            if had_current_db:
                safety_backup = create_backup(
                    "manual", reason="pre-restore safety snapshot", created_by="offline-restore",
                    database_path=live_database, model_path=live_model,
                    backup_dir=root, max_bytes=limit,
                )
                _sqlite_snapshot(live_database, current_db_snapshot)
            if had_current_model:
                shutil.copyfile(live_model, old_model)

            new_db_temp = _copy_to_temporary_file(restored_db, live_database.parent, live_database.name)
            new_model_temp = None
            if restored_model is not None:
                new_model_temp = _copy_to_temporary_file(restored_model, live_model.parent, live_model.name)
            old_db_temp = None
            old_model_temp = None
            swapped_database = False
            swapped_model = False
            sidecars_touched = False
            try:
                if had_current_db:
                    old_db_temp = _copy_to_temporary_file(current_db_snapshot, live_database.parent, f"{live_database.name}.rollback")
                if had_current_model:
                    old_model_temp = _copy_to_temporary_file(old_model, live_model.parent, f"{live_model.name}.rollback")

                sidecars_touched = True
                _restore_sidecars(live_database)
                os.replace(new_db_temp, live_database)
                swapped_database = True
                if new_model_temp is not None:
                    os.replace(new_model_temp, live_model)
                    swapped_model = True
                else:
                    live_model.unlink(missing_ok=True)
                    swapped_model = True
                _fsync_directory(live_database.parent)
                _fsync_directory(live_model.parent)
            except Exception as exc:
                if swapped_database or sidecars_touched:
                    _restore_sidecars(live_database)
                    if old_db_temp is not None and old_db_temp.exists():
                        os.replace(old_db_temp, live_database)
                    else:
                        live_database.unlink(missing_ok=True)
                if swapped_model:
                    if old_model_temp is not None and old_model_temp.exists():
                        os.replace(old_model_temp, live_model)
                    else:
                        live_model.unlink(missing_ok=True)
                raise BackupError("Restore failed while installing files; the prior database/model were rolled back.") from exc
            finally:
                new_db_temp.unlink(missing_ok=True)
                if new_model_temp is not None:
                    new_model_temp.unlink(missing_ok=True)
                if old_db_temp is not None:
                    old_db_temp.unlink(missing_ok=True)
                if old_model_temp is not None:
                    old_model_temp.unlink(missing_ok=True)

    staged_packages_cleared = clear_staged_backups(backup_dir=root)
    logger.warning(
        "Database restore completed package=%s tables=%s credentials_invalidated=%s staged_packages_cleared=%s",
        package.name, manifest["database"]["table_count"], invalidated, staged_packages_cleared,
    )
    return {
        "status": "restored",
        "backup_created_at": manifest["created_at"],
        "table_count": manifest["database"]["table_count"],
        "model_restored": manifest.get("model") is not None,
        "credentials_invalidated": invalidated,
        "pre_restore_backup": safety_backup["filename"] if safety_backup else None,
        "staged_packages_cleared": staged_packages_cleared,
    }
