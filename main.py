from fastapi import FastAPI
from endpoints import router

app = FastAPI()

# Include the router from endpoints.py
app.include_router(router)


