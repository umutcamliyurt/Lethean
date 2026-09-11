from datetime import datetime

from pydantic import BaseModel


class FileMetaResponse(BaseModel):
    id: str
    encrypted_metadata: str
    metadata_iv: str
    content_iv: str
    wrapped_file_key: str
    wrap_iv: str
    size: int
    created_at: datetime

    class Config:
        from_attributes = True


class UsageResponse(BaseModel):
    file_count: int
    total_bytes: int
    quota_bytes: int | None = None


class ShareCreateResponse(BaseModel):
    shareToken: str
    expiresAt: datetime
    maxDownloads: int


class ShareFileResponse(BaseModel):
    content_iv: str
    encrypted_metadata: str
    metadata_iv: str
    downloads_used: int
    max_downloads: int

    class Config:
        from_attributes = True
