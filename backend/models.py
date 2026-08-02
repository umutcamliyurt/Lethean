import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Integer, DateTime, Index
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


Index("ix_files_vault_id", EncryptedFile.vault_id)
