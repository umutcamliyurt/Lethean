from datetime import datetime

from pydantic import BaseModel, Field


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
    deleteToken: str | None = None
    expiresAt: datetime
    maxDownloads: int


class ShareFileResponse(BaseModel):
    content_iv: str
    encrypted_metadata: str
    metadata_iv: str
    downloads_used: int
    max_downloads: int
    expires_at: datetime
    deletable: bool

    class Config:
        from_attributes = True


class RewrapItem(BaseModel):
    file_id: str
    wrapped_file_key: str = Field(..., max_length=4096)
    wrap_iv: str = Field(..., max_length=64)


class VaultRotateRequest(BaseModel):
    new_vault_id: str
    rewraps: list[RewrapItem]


class VaultRotateResponse(BaseModel):
    files_moved: int
    tokens_rebound: int
