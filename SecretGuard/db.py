"""Ciphertext-only SQLite repository for SecretGuard metadata and audit events."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class SecretRepository:
    """Persists metadata, encrypted secret versions, and non-secret audit fields."""

    def __init__(self, database_path: str | Path = "secret_guard.db") -> None:
        self.connection = sqlite3.connect(str(database_path))
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self._create_schema()

    def _create_schema(self) -> None:
        with self.connection:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    secret_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    secret_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    exposed INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    current_version INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (tenant_id, name)
                );
                CREATE TABLE IF NOT EXISTS secret_versions (
                    secret_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    ciphertext BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    auth_tag BLOB NOT NULL,
                    encrypted_dek BLOB NOT NULL,
                    dek_nonce BLOB NOT NULL,
                    dek_auth_tag BLOB NOT NULL,
                    kek_key_id TEXT NOT NULL,
                    kek_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    PRIMARY KEY (secret_id, version),
                    FOREIGN KEY (secret_id) REFERENCES secrets(secret_id)
                );
                CREATE TABLE IF NOT EXISTS secret_permissions (
                    secret_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    operations TEXT NOT NULL,
                    destinations TEXT NOT NULL,
                    allowed_types TEXT NOT NULL,
                    allowed_use INTEGER NOT NULL,
                    allowed_exposed INTEGER NOT NULL,
                    allow_unregistered INTEGER NOT NULL,
                    PRIMARY KEY (secret_id, tenant_id),
                    FOREIGN KEY (secret_id) REFERENCES secrets(secret_id)
                );
                CREATE TABLE IF NOT EXISTS secret_access_audit (
                    event_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    secret_id TEXT NOT NULL,
                    secret_type TEXT NOT NULL,
                    secret_version INTEGER,
                    requester TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    tool_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason_codes TEXT NOT NULL,
                    purpose_hash TEXT NOT NULL,
                    key_version TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    timestamp TEXT NOT NULL
                );
                """
            )

    def register_definition(self, definition: dict[str, Any], tenant_id: str, secret_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connection:
            self.connection.execute(
                """INSERT INTO secrets
                   (secret_id, tenant_id, name, secret_type, source, allowed, exposed, status, current_version, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 0, ?, ?)""",
                (secret_id, tenant_id, definition["name"], definition["secret_type"], definition["source"],
                 int(definition["allowed"]), int(definition["exposed"]), now, now),
            )

    def save_permissions(self, secret_id: str, tenant_id: str, permissions: dict[str, Any]) -> None:
        with self.connection:
            self.connection.execute(
                """INSERT OR REPLACE INTO secret_permissions
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (secret_id, tenant_id, json.dumps(sorted(permissions["operations"])),
                 json.dumps(sorted(permissions["destinations"])), json.dumps(sorted(permissions["types"])),
                 int(permissions["allowed_use"]), int(permissions["allowed_exposed"]),
                 int(permissions["unregistered"])),
            )

    def get_secret(self, secret_id: str, tenant_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM secrets WHERE secret_id=? AND tenant_id=?", (secret_id, tenant_id)
        ).fetchone()
        return dict(row) if row else None

    def list_secrets(self, tenant_id: str) -> tuple[dict[str, Any], ...]:
        rows = self.connection.execute(
            "SELECT * FROM secrets WHERE tenant_id=?", (tenant_id,)
        ).fetchall()
        return tuple(dict(row) for row in rows)

    def get_permissions(self, secret_id: str, tenant_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM secret_permissions WHERE secret_id=? AND tenant_id=?", (secret_id, tenant_id)
        ).fetchone()
        return dict(row) if row else None

    def save_version(self, secret_id: str, version: int, encrypted: dict[str, bytes | str], status: str = "ACTIVE") -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connection:
            self.connection.execute(
                """INSERT INTO secret_versions
                   (secret_id, version, ciphertext, nonce, auth_tag, encrypted_dek, dek_nonce,
                    dek_auth_tag, kek_key_id, kek_version, status, created_at, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)""",
                (secret_id, version, encrypted["ciphertext"], encrypted["nonce"], encrypted["auth_tag"],
                 encrypted["encrypted_dek"], encrypted["dek_nonce"], encrypted["dek_auth_tag"],
                 encrypted["kek_key_id"], encrypted["kek_version"], status, now),
            )
            self.connection.execute(
                "UPDATE secrets SET current_version=?, updated_at=? WHERE secret_id=?",
                (version, now, secret_id),
            )

    def get_version(self, secret_id: str, version: int | None = None) -> dict[str, Any] | None:
        if version is None:
            secret = self.connection.execute(
                "SELECT current_version FROM secrets WHERE secret_id=?", (secret_id,)
            ).fetchone()
            if not secret:
                return None
            version = secret["current_version"]
        row = self.connection.execute(
            "SELECT * FROM secret_versions WHERE secret_id=? AND version=?", (secret_id, version)
        ).fetchone()
        return dict(row) if row else None

    def set_secret_status(self, secret_id: str, status: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self.connection:
            result = self.connection.execute(
                "UPDATE secrets SET status=?, updated_at=? WHERE secret_id=?", (status, now, secret_id)
            )
            self.connection.execute(
                "UPDATE secret_versions SET status=? WHERE secret_id=? AND status='ACTIVE'", (status, secret_id)
            )
        return result.rowcount > 0

    def delete_secret(self, secret_id: str, tenant_id: str) -> bool:
        with self.connection:
            row = self.connection.execute(
                "SELECT status FROM secrets WHERE secret_id=? AND tenant_id=?", (secret_id, tenant_id)
            ).fetchone()
            if row is None:
                return False
            self.connection.execute("DELETE FROM secret_versions WHERE secret_id=?", (secret_id,))
            self.connection.execute("DELETE FROM secret_permissions WHERE secret_id=?", (secret_id,))
            self.connection.execute("DELETE FROM secrets WHERE secret_id=?", (secret_id,))
        return True

    def audit(self, event: dict[str, Any]) -> None:
        with self.connection:
            self.connection.execute(
                     """INSERT INTO secret_access_audit VALUES
                         (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (event["event_id"], event["request_id"], event["secret_id"], event["secret_type"],
                 event.get("secret_version"), event["requester"], event["agent_id"], event["session_id"],
                 event["tool_id"], event["operation"], event["destination"], event["decision"],
                 json.dumps(event["reason_codes"]), event["purpose_hash"], event["key_version"],
                 int(event["success"]), event["timestamp"]),
            )

    def close(self) -> None:
        self.connection.close()
