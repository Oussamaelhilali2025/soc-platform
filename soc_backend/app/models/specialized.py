from sqlalchemy import Column,ForeignKey,String,Integer,JSON,DateTime,PrimaryKeyConstraint
from app.core.database import Base,GUID
class EvenementReseau(Base):
 __tablename__="evenement_reseau"; id_evenement=Column(GUID,ForeignKey("evenement.id_evenement",ondelete="CASCADE"),primary_key=True); adresse_ip_source=Column(String(45),nullable=False); adresse_ip_destination=Column(String(45),nullable=False); port_source=Column(Integer); port_destination=Column(Integer); protocole=Column(String(20)); direction=Column(String(20)); action_reseau=Column(String(30))
class EvenementHTTP(Base):
 __tablename__="evenement_http"; id_evenement=Column(GUID,ForeignKey("evenement.id_evenement",ondelete="CASCADE"),primary_key=True); methode_http=Column(String(10)); url=Column(String); uri=Column(String(255)); hostname=Column(String(255)); port=Column(Integer); code_statut=Column(Integer); taille_reponse=Column(Integer); headers_reponse=Column(JSON); referer=Column(String); user_agent=Column(String); payload=Column(String)
class EvenementProcessus(Base):
 __tablename__="evenement_processus"; id_evenement=Column(GUID,ForeignKey("evenement.id_evenement",ondelete="CASCADE"),primary_key=True); nom_processus=Column(String(255)); chemin_processus=Column(String); pid=Column(Integer); ppid=Column(Integer); utilisateur=Column(String(100)); niveau_integrite=Column(String(20)); ligne_commande=Column(String); hash_processus=Column(String(64)); nom_processus_parent=Column(String(255))
