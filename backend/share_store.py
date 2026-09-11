import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, update
from sqlalchemy.orm import Session

import storage
from models import EncryptedFile, ShareToken

DEFAULT_SHARE_TTL_SECONDS = 7 * 24 * 3600
DEFAULT_MAX_DOWNLOADS = 1


class TooManyActiveSharesError(Exception):
    pass

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def count_active_shares(db: Session, file_id: str) -> int:
    now = datetime.now(timezone.utc)
    return (
        db.query(func.count(ShareToken.id))
        .filter(ShareToken.file_id == file_id, ShareToken.expires_at > now)
        .scalar()
    ) or 0


def create_share(
    db: Session,
    file_id: str,
    vault_id: str,
    ttl_seconds: int = DEFAULT_SHARE_TTL_SECONDS,
    max_downloads: int = DEFAULT_MAX_DOWNLOADS,
    max_active_per_file: int | None = None,
) -> tuple[str, datetime, int]:
    if max_downloads < 1:
        max_downloads = 1

    if max_active_per_file is not None and count_active_shares(db, file_id) >= max_active_per_file:
        raise TooManyActiveSharesError(
            f"file {file_id} already has {max_active_per_file} or more active share links"
        )

    raw_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl_seconds)

    db.add(ShareToken(
        token_hash=_hash_token(raw_token),
        file_id=file_id,
        vault_id=vault_id,
        max_downloads=max_downloads,
        download_count=0,
        created_at=now,
        expires_at=expires_at,
    ))
    db.commit()

    return raw_token, expires_at, max_downloads


def peek_share(db: Session, raw_token: str) -> tuple[EncryptedFile, int, int] | None:
    now = datetime.now(timezone.utc)
    share = (
        db.query(ShareToken)
        .filter(
            ShareToken.token_hash == _hash_token(raw_token),
            ShareToken.expires_at > now,
        )
        .first()
    )
    if share is None:
        return None
    record = db.query(EncryptedFile).filter(EncryptedFile.id == share.file_id).first()
    if record is None:
        return None
    return record, share.download_count, share.max_downloads


def delete_via_share(db: Session, raw_token: str) -> bool:
    now = datetime.now(timezone.utc)
    share = (
        db.query(ShareToken)
        .filter(
            ShareToken.token_hash == _hash_token(raw_token),
            ShareToken.expires_at > now,
        )
        .first()
    )
    if share is None:
        return False

    record = db.query(EncryptedFile).filter(EncryptedFile.id == share.file_id).first()
    if record is None:
        return False
    storage_path = record.storage_path

    result = db.execute(delete(EncryptedFile).where(EncryptedFile.id == share.file_id))
    db.commit()
    if result.rowcount != 1:
        return False

    storage.shred_blob(storage_path)
    return True


def claim_share(db: Session, raw_token: str) -> EncryptedFile | None:
    now = datetime.now(timezone.utc)
    token_hash = _hash_token(raw_token)

    result = db.execute(
        update(ShareToken)
        .where(
            ShareToken.token_hash == token_hash,
            ShareToken.expires_at > now,
            ShareToken.download_count < ShareToken.max_downloads,
        )
        .values(download_count=ShareToken.download_count + 1)
    )
    db.commit()

    if result.rowcount != 1:
        return None

    share = db.query(ShareToken).filter(ShareToken.token_hash == token_hash).first()
    if share is None:
        return None
    return db.query(EncryptedFile).filter(EncryptedFile.id == share.file_id).first()


def revoke_shares_for_file(db: Session, file_id: str, vault_id: str) -> int:
    result = db.execute(
        delete(ShareToken).where(ShareToken.file_id == file_id, ShareToken.vault_id == vault_id)
    )
    db.commit()
    return result.rowcount


def purge_expired(db: Session) -> int:
    now = datetime.now(timezone.utc)
    result = db.execute(delete(ShareToken).where(ShareToken.expires_at <= now))
    db.commit()
    return result.rowcount
