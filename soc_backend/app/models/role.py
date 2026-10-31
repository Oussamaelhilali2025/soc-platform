import uuid
from sqlalchemy import Column,String
from sqlalchemy.orm import relationship
from app.core.database import Base,GUID
class Role(Base):
    __tablename__='role'; id_role=Column(GUID,primary_key=True,default=uuid.uuid4); nom=Column(String(50),unique=True,nullable=False); description=Column(String)
    users=relationship('Utilisateur',secondary='utilisateur_role',back_populates='roles'); permissions=relationship('Permission',secondary='role_permission',back_populates='roles')
