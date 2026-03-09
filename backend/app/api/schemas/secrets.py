from pydantic import BaseModel, Field


class SecretCreateRequest(BaseModel):
    key: str = Field(min_length=1, max_length=120)
    value: str = Field(min_length=0)


class SecretRotateRequest(BaseModel):
    value: str = Field(min_length=0)


class SecretKeyResponse(BaseModel):
    key: str


class SecretValueResponse(BaseModel):
    key: str
    value: str

