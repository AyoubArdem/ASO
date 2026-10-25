from sqlalchemy import Column, ForeignKey, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class MetaAgent(Base):
    __tablename__ = "meta_agents"

    agent_id = Column(String, primary_key=True, nullable=False, index=True)
    agent_name = Column(String, nullable=False)
    agent_version = Column(String, nullable=False)
    agent_developper = Column(String, nullable=False)
    agent_description = Column(Text, nullable=False)


class Infos(Base):
    __tablename__ = "infos"
    table_name = __tablename__

    id = Column(String, primary_key=True)
    agent = Column(String, ForeignKey("meta_agents.agent_id"), nullable=False, index=True)
    session_id = Column(String, nullable=False, index=True)
    request_id = Column(String, nullable=False, unique=True)
    task_id = Column(String, nullable=False, index=True)


class LLM_QUERY_AUDIT(Base):
    __tablename__ = "llm_query_audits"

    id = Column(String, primary_key=True)
    agent = Column(String, ForeignKey("meta_agents.agent_id"), nullable=False, index=True)
    component = Column(String, nullable=False)
    action = Column(String, nullable=False)
    reasons = Column(Text, nullable=False)
