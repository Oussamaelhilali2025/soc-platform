from sqlalchemy import Column,String,Integer,Boolean,DateTime,JSON,Text,Numeric,ForeignKey
import uuid
from app.core.database import Base,GUID
class IOC(Base):
    __tablename__="ioc"
    id_ioc=Column(GUID, primary_key=True, default=uuid.uuid4)
    type_ioc=Column(String(30), nullable=False)
    valeur=Column(Text, nullable=False)
    is_ioc=Column(Boolean)
    date_premiere_observation=Column(DateTime(6), nullable=False)
    date_derniere_observation=Column(DateTime(6), nullable=False)
