from pydantic import BaseModel
from sqlalchemy import Column, String, Float, DateTime, ForeignKey 
from sqlalchemy.orm import relationship , declarative_base
from DecisionEngine.db import Infos

infos_agent = Infos().table_name
Base = declarative_base()

class agentModel(BaseModel):
    agent_id : str
    operation : str
    store : str
    permissions : list[str]

class guardActionModel(BaseModel):
    action_id : str
    agent : agentModel
    action : str
    risk_score : float
    confidence : float
    timestamp : str

class AgentOperations(Base):
    __tablename__ = 'agentsOperations'

    id = Column(String, primary_key=True)
    agent_id = Column(String, ForeignKey("infos_agent.agent_id"))
    operation = Column(String)
    store = Column(String)
    permissions = Column(String)  


class guardAction(Base):
    __tablename__ = 'guard_actions'

    action_id = Column(String, primary_key=True)
    agent_id = Column(String, ForeignKey('agentsOperations.agent_id'))
    action = Column(String)
    risk_score = Column(Float)
    confidence = Column(Float)
    timestamp = Column(DateTime)

    agent = relationship("Agent", back_populates="guard_actions")