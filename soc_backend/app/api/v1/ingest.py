from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.services.event_ingestion_service import ingest_wazuh_event
router=APIRouter(prefix='/ingest',tags=['ingestion'])
@router.post('/wazuh')
def wazuh(payload:dict,db:Session=Depends(get_db)):
    try:return ingest_wazuh_event(db,payload)
    except Exception as e: db.rollback(); raise HTTPException(400,str(e))
