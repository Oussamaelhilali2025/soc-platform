import uuid
from sqlalchemy import Column,String
from sqlalchemy.orm import relationship
from app.core.database import Base,GUID
class Permission(Base):
    __tablename__='permission'; id_permission=Column(GUID,primary_key=True,default=uuid.uuid4); code=Column(String(50),unique=True,nullable=False); description=Column(String)
    roles=relationship('Role',secondary='role_permission',back_populates='permissions')
