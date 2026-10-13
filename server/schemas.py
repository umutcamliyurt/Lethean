from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


class FileMetaResponse(BaseModel):
    id: str
    encrypted_metadata: str
    metadata_iv: str
    content_iv: str
    wrapped_file_key: str
    wrap_iv: str
    size: int
    created_at: datetime

    _tz = field_validator("created_at")(_utc)

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

    _tz = field_validator("expiresAt")(_utc)


class ShareFileResponse(BaseModel):
    content_iv: str
    encrypted_metadata: str
    metadata_iv: str
    downloads_used: int
    max_downloads: int
    expires_at: datetime
    deletable: bool

    _tz = field_validator("expires_at")(_utc)

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


class UploadInitRequest(BaseModel):
    content_iv: str = Field(..., max_length=64)
    encrypted_metadata: str = Field(..., max_length=65536)
    metadata_iv: str = Field(..., max_length=64)
    wrapped_file_key: str = Field(..., max_length=4096)
    wrap_iv: str = Field(..., max_length=64)
    part_count: int = Field(..., ge=1)
    part_size: int = Field(..., ge=1)
    total_size: int = Field(..., ge=1)


class UploadInitResponse(BaseModel):
    upload_id: str


class UploadStatusResponse(BaseModel):
    received: list[int]


class DuressPutRequest(BaseModel):
    blob: str = Field(..., max_length=2048)
    shred_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class ShredRequest(BaseModel):
    secret: str = Field(..., max_length=128)
