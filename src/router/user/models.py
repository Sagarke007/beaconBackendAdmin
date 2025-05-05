"""User model"""

from pydantic import Field

import re
import html
from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator
from shared.utils import validate_password

import root_dir_getter  # pylint: disable=unused-import

root_dir_getter.set_root_dir(__file__)  # pylint: disable=wrong-import-position


class UserRegistration(BaseModel):
    """User registration Pydantic model"""

    first_name: str
    last_name: str
    nick_name: Optional[str] = ""
    email_address: EmailStr
    password: str
    phone_number: Optional[str] = None  # ← made optional
    register_type: str = "direct"

    @field_validator("first_name", "last_name", "nick_name")
    def validate_name_fields(cls, name_value: str) -> str:
        max_length = 20
        min_length = 2
        if not name_value.strip():
            raise ValueError("Name cannot be empty or just whitespace.")
        if len(name_value) < min_length:
            raise ValueError(f"Name must be greater than {min_length} characters.")
        if len(name_value) > max_length:
            raise ValueError(f"Name must not exceed {max_length} characters.")
        if not re.match(r"^[a-zA-Z\s]+$", name_value):
            raise ValueError("Name must contain only alphabets and spaces.")
        return html.escape(name_value)

    @field_validator("password")
    def check_password(cls, password_value):
        return validate_password(password_value)

    @field_validator("email_address")
    def validate_email_length(cls, email_value: EmailStr) -> EmailStr:
        max_length = 100
        if len(email_value) > max_length:
            raise ValueError(f"Email address must not exceed {max_length} characters.")
        return email_value

    @field_validator("phone_number")
    def validate_phone_number(cls, phone_number_value):
        if phone_number_value:
            if not phone_number_value.isdigit() or len(phone_number_value) != 10:
                raise ValueError("Phone number must be a 10-digit numeric value.")
        return phone_number_value


class LoginRequest(BaseModel):
    """user Login pydantic model"""

    username: EmailStr
    password: str


class UserAccessUpdatePayload(BaseModel):
    """
    Class to handle user access update payload.
    """

    email: EmailStr  # Valid email address
    is_active: Optional[bool] = Field(
        None, description="Must be either true (active) or false (inactive)"
    )  # True or False for active status

    class Config:
        """
        Strips whitespace from the string inputs
        """

        str_strip_whitespace = True


class PlatformUpdatePayload(BaseModel):
    """
    validation for the platform
    """

    email: EmailStr  # User's email address (required)
    IsMarketSavant: Optional[int] = Field(
        None, ge=0, le=1, description="0 for inactive, 1 for active"
    )
    IsOfferSavant: Optional[int] = Field(
        None, ge=0, le=1, description="0 for inactive, 1 for active"
    )
    IsContract: Optional[int] = Field(
        None, ge=0, le=1, description="0 for inactive, 1 for active"
    )

    class Config:
        """
        Strips whitespace from the string inputs
        """

        str_strip_whitespace = True


class TokenPayload(BaseModel):
    """
    class to  to get google token
    """

    google_token: str


class ChangePasswordRequest(BaseModel):
    """
    class to get current password and new password
    """

    current_password: str = Field(..., title="Current Password (Base64-encoded)")
    new_password: str = Field(..., title="New Password (Base64-encoded)")
    confirm_password: str = Field(..., title="Confirm New Password (Base64-encoded)")


class UserEmailRequest(BaseModel):
    """
    Class to get the Base64-encoded email.
    """

    email: str = Field(..., title="Base64-encoded Email")
