import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone

from sqlalchemy.orm import Session

import token_store
from models import DuressSlot, ShredHash

MAX_BLOB_LEN = 2048
SHRED_SECRET_BYTES = 32


def random_decoy_blob() -> str:
    return json.dumps(
        {
            "salt": base64.b64encode(secrets.token_bytes(16)).decode(),
            "verifier": secrets.token_hex(32),
            "encVaultId": base64.b64encode(secrets.token_bytes(80)).decode(),
            "iv": base64.b64encode(secrets.token_bytes(12)).decode(),
            "kdfVersion": 2,
        },
        separators=(",", ":"),
    )


def get_or_create_slot(db: Session, token_hash: str) -> DuressSlot:
    slot = db.get(DuressSlot, token_hash)
    if slot is None:
        slot = DuressSlot(token_hash=token_hash, blob=random_decoy_blob(), written=False)
        db.add(slot)
        db.commit()
        db.refresh(slot)
    return slot


def write_slot(db: Session, token_hash: str, blob: str, vault_id: str, shred_hash: str | None) -> None:
    slot = db.get(DuressSlot, token_hash)
    now = datetime.now(timezone.utc)
    if slot is None:
        db.add(DuressSlot(token_hash=token_hash, blob=blob, written=True, updated_at=now))
    else:
        slot.blob, slot.written, slot.updated_at = blob, True, now
    if shred_hash is not None:
        other = db.query(ShredHash).filter(ShredHash.shred_hash == shred_hash, ShredHash.vault_id != vault_id).first()
        if other is None:
            row = db.get(ShredHash, vault_id)
            if row is None:
                db.add(ShredHash(vault_id=vault_id, shred_hash=shred_hash))
            else:
                row.shred_hash = shred_hash
    db.commit()


def vault_for_secret(db: Session, secret_b64: str) -> str | None:
    try:
        secret = base64.b64decode(secret_b64, validate=True)
    except Exception:
        return None
    if len(secret) != SHRED_SECRET_BYTES:
        return None
    row = db.query(ShredHash).filter(ShredHash.shred_hash == hashlib.sha256(secret).hexdigest()).first()
    return row.vault_id if row else None


def on_vault_wiped(db: Session, vault_id: str) -> None:
    db.query(ShredHash).filter(ShredHash.vault_id == vault_id).delete(synchronize_session=False)
    now = datetime.now(timezone.utc)
    for token_hash in token_store.hashes_for_vault(vault_id):
        slot = db.get(DuressSlot, token_hash)
        if slot is not None:
            slot.blob, slot.updated_at = random_decoy_blob(), now


def on_vault_rotated(db: Session, old_vault_id: str, new_vault_id: str) -> None:
    db.query(ShredHash).filter(ShredHash.vault_id == new_vault_id).delete(synchronize_session=False)
    db.query(ShredHash).filter(ShredHash.vault_id == old_vault_id).update(
        {"vault_id": new_vault_id}, synchronize_session=False
    )


def on_token_revoked(db: Session, token_hash: str) -> None:
    db.query(DuressSlot).filter(DuressSlot.token_hash == token_hash).delete(synchronize_session=False)
    db.commit()
