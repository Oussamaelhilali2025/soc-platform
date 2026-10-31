from sqlalchemy import Table,Column,ForeignKey
from app.core.database import Base,GUID
utilisateur_role=Table('utilisateur_role',Base.metadata,Column('id_utilisateur',GUID,ForeignKey('utilisateur.id_utilisateur',ondelete='CASCADE'),primary_key=True),Column('id_role',GUID,ForeignKey('role.id_role',ondelete='CASCADE'),primary_key=True))
role_permission=Table('role_permission',Base.metadata,Column('id_role',GUID,ForeignKey('role.id_role',ondelete='CASCADE'),primary_key=True),Column('id_permission',GUID,ForeignKey('permission.id_permission',ondelete='CASCADE'),primary_key=True))
