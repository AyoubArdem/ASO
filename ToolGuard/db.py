"""Encrypted Tool Guard persistence models.

Sensitive fields are ciphertext at rest. Encryption keys must be supplied by
the application through ``TOOL_GUARD_KEY`` or an external secret manager.
"""

from __future__ import annotations

import base64
import json
import os
import importlib
from datetime import datetime
from typing import Any


def _fernet():
    try:
        return importlib.import_module("cryptography.fernet").Fernet
    except ImportError as error:
        raise RuntimeError("install cryptography to use encrypted Tool Guard storage") from error


class EncryptedField:
    def __init__(self, key: str | bytes | None = None) -> None:
        configured = key or os.environ.get("TOOL_GUARD_KEY")
        if not configured:
            raise RuntimeError("TOOL_GUARD_KEY must be configured")
        raw = configured.encode() if isinstance(configured, str) else configured
        self._cipher = _fernet()(raw)

    def encrypt(self, value: Any) -> str:
        payload = json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":")).encode()
        return self._cipher.encrypt(payload).decode()

    def decrypt(self, value: str) -> Any:
        return json.loads(self._cipher.decrypt(value.encode()).decode())


try:
    _sqlalchemy = importlib.import_module("sqlalchemy")
    _orm = importlib.import_module("sqlalchemy.orm")
except ImportError:
    Base = None
else:
    Boolean = _sqlalchemy.Boolean
    Column = _sqlalchemy.Column
    DateTime = _sqlalchemy.DateTime
    Float = _sqlalchemy.Float
    ForeignKey = _sqlalchemy.ForeignKey
    String = _sqlalchemy.String
    Text = _sqlalchemy.Text
    declarative_base = _orm.declarative_base
    Base = declarative_base()

    class ToolDefinition(Base):
        __tablename__ = "tool_definitions"
        tool_id = Column(String, primary_key=True)
        name = Column(String, nullable=False)
        description = Column(Text, nullable=False)
        purpose = Column(Text, nullable=False)
        input_schema = Column(Text, nullable=False)
        output_schema = Column(Text, nullable=False)
        security_metadata = Column(Text, nullable=False)
        created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    class ToolRequest(Base):
        __tablename__ = "tool_requests"
        request_id = Column(String, primary_key=True)
        tool_id = Column(String, ForeignKey("tool_definitions.tool_id"), nullable=False)
        agent_id = Column(String, nullable=False)
        session_id = Column(String, nullable=False)
        task_id = Column(String, nullable=False)
        request_data = Column(Text, nullable=False)
        created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    class ToolDecision(Base):
        __tablename__ = "tool_decisions"
        event_id = Column(String, primary_key=True)
        request_id = Column(String, nullable=False)
        tool_id = Column(String, nullable=False)
        agent_id = Column(String, nullable=False)
        decision = Column(String, nullable=False)
        risk_score = Column(Float, nullable=False)
        encrypted_reasons = Column(Text, nullable=False)
        phase = Column(String, nullable=False)
        created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    class ToolExecutionRecord(Base):
        __tablename__ = "tool_execution_records"
        execution_id = Column(String, primary_key=True)
        request_id = Column(String, nullable=False)
        tool_id = Column(String, nullable=False)
        agent_id = Column(String, nullable=False)
        encrypted_result = Column(Text, nullable=False)
        success = Column(Boolean, nullable=False)
        duration_ms = Column(Float, nullable=False)
        created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    class ToolHistory(Base):
        __tablename__ = "tool_histories"
        history_id = Column(String, primary_key=True)
        request_id = Column(String, nullable=False)
        tool_id = Column(String, nullable=False)
        agent_id = Column(String, nullable=False)
        pre_decision = Column(String, nullable=False)
        risk_score_pre = Column(Float, nullable=False)
        post_decision = Column(String, nullable=False)
        risk_score_post = Column(Float, nullable=False)
        trusted = Column(Boolean, nullable=False, default=False)
        created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
