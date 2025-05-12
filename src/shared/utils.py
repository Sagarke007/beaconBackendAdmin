"""
Utility functions for password validation, hashing, and verification.

This module provides helper functions to:
- Validate the strength and correctness of passwords based on specific criteria.
- Hash passwords securely using bcrypt.
- Verify hashed passwords against plain text passwords.

Dependencies:
- re: For regular expression operations.
- bcrypt: For secure password hashing and verification.

Functions:
- validate_password(password: str) -> str: Validates a password based on length, character types, and allowed characters.
- hash_password(password: str) -> str: Hashes a password using bcrypt.
- verify_password(plain_password: str, hashed_password: str) -> bool: Verifies if a plain password matches a hashed password.
"""

import base64
import re
import secrets
import os
import bcrypt
from faker import Faker
from pydantic import BaseModel
from typing import get_args, get_origin, Union
import random


from dotenv import load_dotenv

load_dotenv("../.env")

SECRET_KEY = os.environ.get("USER_AUTH_SECRET_KEY")

fake = Faker()


def validate_password(password: str) -> str:
    """Validate password correctness.

    Args:
        password (str): The password to validate.

    Raises:
        ValueError: If the password does not meet the required criteria.

    Returns:
        str: The validated password.
    """
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one number.")
    if not re.search(r"[@$!%*?&#]", password):
        raise ValueError(
            "Password must contain at least one special character (@$!%*?&#)."
        )
    if not re.match(r"^[A-Za-z\d@$!%*?&#]+$", password):
        raise ValueError("Password contains invalid characters.")

    return password


# Helper functions for password hashing and verification
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies if the plain password matches the hashed password"""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


def hash_password(password: str) -> str:
    """Hashes the given password using bcrypt"""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def generate_secure_password() -> str:
    """Generates a secure random password."""
    return secrets.token_urlsafe(8)  # 12-character secure password


def encode_to_base64(data: str) -> str:
    """Encodes a string to Base64 (standard encoding)."""
    return base64.b64encode(data.encode("utf-8")).decode("utf-8")


def decode_from_base64(data: str) -> str:
    """Decodes a Base64-encoded string."""
    return base64.b64decode(data.encode("utf-8")).decode("utf-8")


from faker import Faker
import random
import json
from typing import Dict, Any, Optional

fake = Faker()


def generate_fake_value(field_name: str, field_type: str) -> Optional[Any]:
    """Generate appropriate fake data based on field name and type string"""
    field_name = field_name.lower()

    # Handle string types
    if field_type == "string":
        if field_name in {"email", "email_address", "username"}:
            return fake.unique.email()
        if "password" in field_name:
            return fake.password(length=12, special_chars=True)
        if "name" in field_name:
            if "first" in field_name:
                return fake.first_name()
            if "last" in field_name:
                return fake.last_name()
            if "nick" in field_name or "user" in field_name:
                return fake.user_name()
            return fake.name()
        if "phone" in field_name:
            return fake.phone_number()
        if "token" in field_name:
            return fake.uuid4()
        if "otp" in field_name:
            return str(random.randint(100000, 999999))
        if "url" in field_name:
            return fake.url()
        if "date" in field_name or "time" in field_name:
            return fake.iso8601()
        return fake.word()

    # Handle other types
    elif field_type == "boolean":
        return random.choice([True, False])
    elif field_type == "integer":
        return random.randint(1, 100)
    elif field_type == "number" or field_type == "float":
        return round(random.uniform(1, 100), 2)

    # Fallback for unknown types
    return None


def enhance_endpoints_with_fake_data(endpoints_data: Dict[str, Any]) -> Dict[str, Any]:
    """Enhance each endpoint with generated fake_data based on its schema"""
    enhanced_endpoints = []

    for endpoint in endpoints_data:
        # Create a copy of the endpoint to avoid modifying the original
        enhanced_endpoint = endpoint.copy()

        if (
            "schema" in enhanced_endpoint
            and "request_body" in enhanced_endpoint["schema"]
        ):
            # Generate fake data
            fake_payload = {
                field_name: generate_fake_value(field_name, field_type)
                for field_name, field_type in enhanced_endpoint["schema"][
                    "request_body"
                ].items()
            }

            # Add the fake_data at the same level as schema
            enhanced_endpoint["fake_data"] = fake_payload

        enhanced_endpoints.append(enhanced_endpoint)

    return enhanced_endpoints
