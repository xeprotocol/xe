from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = Field(default="postgresql+asyncpg://dao:dao@localhost:5432/dao", alias="DATABASE_URL")
    xe_node_url: str = Field(default="https://ldn.core.test.network", alias="XE_NODE_URL")
    # The network this deployment is for, as the node at XE_NODE_URL names itself (`network_id` at GET /node).
    # Nothing is signed for any other, and with this unset nothing is signed at all (XE-12620).
    xe_network_id: str = Field(default="", alias="XE_NETWORK_ID")
    public_base_url: str = Field(default="http://localhost:8000", alias="PUBLIC_BASE_URL")
    config_dir: Path = Field(default=Path("config"), alias="DAO_CONFIG_DIR")
    signer_keyfile: Path = Field(default=Path("secrets/signer.json"), alias="DAO_SIGNER_KEYFILE")
    signer_passphrase: str = Field(default="", alias="DAO_SIGNER_PASSPHRASE")
    directory_node_peer: str = Field(default="", alias="DAO_DIRECTORY_NODE_PEER")
    git_commit: str = Field(default=os.environ.get("DAO_GIT_COMMIT", "unknown"), alias="GIT_COMMIT")
    log_level: str = Field(default="info", alias="LOG_LEVEL")

    @field_validator("log_level")
    @classmethod
    def _a_level(cls, value: str) -> str:
        # read by both entry points (`logging_level`); a name that is not a level stops the process rather
        # than leaving it at a level nobody chose (XE-10085)
        name = value.strip().lower()
        if name not in ("debug", "info", "warning", "error", "critical"):
            raise ValueError("LOG_LEVEL must be one of debug, info, warning, error, critical")
        return name

    @property
    def logging_level(self) -> int:
        return getattr(logging, self.log_level.upper())

    @property
    def sync_database_url(self) -> str:
        return self.database_url.replace("+asyncpg", "+psycopg")


@lru_cache
def get_settings() -> Settings:
    return Settings()
