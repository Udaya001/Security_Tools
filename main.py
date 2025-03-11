from fastapi import FastAPI
from endpoints import router

app = FastAPI()

# Include the router from endpoints.py
app.include_router(router,prefix='/api/v1',tags=['Security Scanner'])


