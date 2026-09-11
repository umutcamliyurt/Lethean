import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Index
from database import Base


def gen_uuid():
    return str(uuid.uuid4())


class EncryptedFile(Base):
    __tablename__ = "files"

    id = Column(String, primary_key=True, default=gen_uuid)
    vault_id = Column(String, nullable=False)

    encrypted_metadata = Column(String, nullable=False)
    metadata_iv = Column(String, nullable=False)

    content_iv = Column(String, nullable=False)
    wrapped_file_key = Column(String, nullable=False)
    wrap_iv = Column(String, nullable=False)

    storage_path = Column(String, nullable=False)
    size = Column(Integer, nullable=False)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


Index("ix_files_vault_created", EncryptedFile.vault_id, EncryptedFile.created_at, EncryptedFile.id)


class ShareToken(Base):

    __tablename__ = "share_tokens"

    id = Column(String, primary_key=True, default=gen_uuid)
    token_hash = Column(String, nullable=False, unique=True, index=True)

    file_id = Column(String, ForeignKey("files.id", ondelete="CASCADE"), nullable=False, index=True)
    vault_id = Column(String, nullable=False)

    max_downloads = Column(Integer, nullable=False, default=1)
    download_count = Column(Integer, nullable=False, default=0)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)


Index("ix_share_tokens_file", ShareToken.file_id)