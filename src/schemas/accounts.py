from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserCreateSchema(UserLoginRequestSchema):

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        accounts_validators.validate_password_strength(value)
        return value

UserRegistrationRequestSchema = UserCreateSchema

class UserCreateResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class UserActivateRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteSchema(PasswordResetRequestSchema):
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        accounts_validators.validate_password_strength(value)
        return value


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


class UserLoginResponseSchema(TokenRefreshResponseSchema):
    refresh_token: str
    token_type: str


class MessageResponseSchema(BaseModel):
    message: str
