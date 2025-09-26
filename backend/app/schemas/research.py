from pydantic import BaseModel

class ResearchCreate(BaseModel):
    title: str
    description: str
