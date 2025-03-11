from pydantic import BaseModel
from typing import Optional

class ScanRequest(BaseModel):
    target_url: str
    mode: Optional[str] = "security"  
