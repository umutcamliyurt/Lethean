import re
from dataclasses import dataclass

from fastapi import Header, HTTPException

import token_store

_VAULT_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_ACCESS_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")


def get_vault_id(authorization: str = Header(...)) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer vault ID")
    vault_id = authorization.removeprefix("Bearer ").strip().lower()
    if not _VAULT_ID_RE.match(vault_id):
        raise HTTPException(status_code=400, detail="Malformed vault ID")
    return vault_id


@dataclass
class UploadAuthorization:
    vault_id: str
    quota_bytes: int


def require_upload_authorization(
    authorization: str = Header(alias="Authorization"),
    x_access_token: str | None = Header(default=None, alias="X-Access-Token"),
) -> UploadAuthorization:
    resolved_vault_id = get_vault_id(authorization)

    if not x_access_token:
        raise HTTPException(status_code=401, detail="Missing X-Access-Token header")

    access_token = x_access_token.strip().lower()
    if not _ACCESS_TOKEN_RE.match(access_token):
        raise HTTPException(status_code=400, detail="Malformed access token")

    record = token_store.bind_to_vault(access_token, resolved_vault_id)
    if record is None:
        raise HTTPException(status_code=403, detail="Invalid access token, or it's already bound to a different vault")

    return UploadAuthorization(vault_id=resolved_vault_id, quota_bytes=token_store.quota_bytes_for(record))
