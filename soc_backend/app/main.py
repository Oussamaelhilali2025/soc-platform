from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1 import api_router
app=FastAPI(title=settings.PROJECT_NAME,version='1.0.0',openapi_url=f'{settings.API_V1_STR}/openapi.json',docs_url=f'{settings.API_V1_STR}/docs',redoc_url=f'{settings.API_V1_STR}/redoc')
app.add_middleware(CORSMiddleware,allow_origins=settings.BACKEND_CORS_ORIGINS,allow_credentials=True,allow_methods=['*'],allow_headers=['*'])
app.include_router(api_router,prefix=settings.API_V1_STR)
@app.get('/health')
def health(): return {'status':'ok','service':'soc-backend'}
