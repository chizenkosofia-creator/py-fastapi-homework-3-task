from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import TokenExpiredError, InvalidTokenError
from schemas.accounts import (
    UserCreateResponseSchema,
    UserCreateSchema,
    MessageResponseSchema,
    UserActivateRequestSchema,
    PasswordResetRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    PasswordResetCompleteSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.token_manager import JWTAuthManager

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserCreateResponseSchema,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {
            "description": "A user with this email already exists.",
        },
        500: {
            "description": "An error occurred during user creation.",
        },
    },
)
async def user_registration(
    user_data: UserCreateSchema,
    db: AsyncSession = Depends(get_db),
) -> UserModel:
    result = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user_group = result.scalar_one()

    result = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=cast(int, user_group.id),
    )

    activation_token = ActivationTokenModel(user=user)

    db.add(user)
    db.add(activation_token)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    await db.refresh(user)

    return user


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
    user_data: UserActivateRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    result = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == cast(int, user.id),
            ActivationTokenModel.token == user_data.token,
        )
    )
    activation_token = result.scalar_one_or_none()

    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = cast(datetime, activation_token.expires_at)

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        await db.delete(activation_token)
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    await db.delete(activation_token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def request_password_reset(
    user_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager),
) -> dict:
    generic_response = {
        "message": "If you are registered, you will receive an email with instructions."
    }

    try:
        result = await db.execute(
            select(UserModel).where(UserModel.email == user_data.email)
        )
        user = result.scalar_one_or_none()

        # Якщо користувача немає або він неактивний — повертаємо універсальну відповідь БЕЗ помилок
        if not user or not user.is_active:
            return generic_response

        # Перевірка та видалення старого токена, якщо існує
        result = await db.execute(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == cast(int, user.id)
            )
        )
        existing_token = result.scalar_one_or_none()

        if existing_token:
            await db.delete(existing_token)

        # Генерація токена скидання пароля
        token_str = jwt_manager.create_password_reset_token({"sub": str(user.id)})
        reset_token = PasswordResetTokenModel(
            token=token_str,
            user_id=cast(int, user.id),
            expires_at=jwt_manager.get_token_expiration(token_str),
        )
        db.add(reset_token)

        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return generic_response


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def complete_password_reset(
    user_data: PasswordResetCompleteSchema,
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == cast(int, user.id),
        )
    )
    reset_token = result.scalar_one_or_none()

    if not reset_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    if reset_token.token != user_data.token:
        await db.delete(reset_token)
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    expires_at = cast(datetime, reset_token.expires_at)

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        await db.delete(reset_token)
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        user.password = user_data.password

        await db.delete(reset_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return {"message": "Password reset successfully."}


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def user_login(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
) -> dict:
    result = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    user = result.scalar_one_or_none()

    if not user or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    user_id = cast(int, user.id)

    access_token = jwt_manager.create_access_token(data={"user_id": user_id})

    refresh_token = jwt_manager.create_refresh_token(data={"user_id": user_id})

    refresh_token_record = RefreshTokenModel.create(
        user_id=user_id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token,
    )

    db.add(refresh_token_record)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    token_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> dict:
    try:
        payload = jwt_manager.decode_refresh_token(
            token_data.refresh_token
        )
    except TokenExpiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        ) from exc
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token.",
        ) from exc

    result = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == token_data.refresh_token
        )
    )
    refresh_token = result.scalar_one_or_none()

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )
    user_id = cast(int, payload["user_id"])

    result = await db.execute(
        select(UserModel).where(
            UserModel.id == user_id
        )
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token(
        data={"user_id": user_id}
    )

    return {
        "access_token": access_token,
    }
