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
import random
from typing import Dict, Any

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


def generate_fake_value(field_name: str, field_type: str) -> Any:
    """Generate appropriate fake data based on field name and type"""
    field_name = field_name.lower()
    field_type = field_type.lower()

    if field_type == "string":
        if any(email_key in field_name for email_key in ["email", "mail"]):
            return fake.email()
        if "password" in field_name:
            return fake.password(length=12, special_chars=True)
        if "phone" in field_name:
            return fake.phone_number()
        if "name" in field_name:
            if "first" in field_name:
                return fake.first_name()
            if "last" in field_name:
                return fake.last_name()
            return fake.name()
        if any(id_key in field_name for id_key in ["token", "uuid", "id"]):
            return fake.uuid4()
        if "url" in field_name:
            return fake.url()
        if any(date_key in field_name for date_key in ["date", "time"]):
            return fake.iso8601()
        return fake.word()

    if field_type in ["integer", "number"]:
        return random.randint(1, 100)
    if field_type == "float":
        return round(random.uniform(1, 100), 2)
    if field_type == "boolean":
        return random.choice([True, False])

    return None


def enhance_endpoints_with_fake_data(schema: Dict[str, str]) -> Dict[str, Any]:
    """Generate fake data for each field in the schema"""
    return {
        field: generate_fake_value(field, field_type)
        for field, field_type in schema.items()
    }


def create_dsn(user_id: str, project_id: str) -> str:
    """Generate a Data Source Name (DSN) for database connections."""
    raw_string = f"{user_id}:{project_id}:{SECRET_KEY}"
    dsn = base64.urlsafe_b64encode(raw_string.encode()).decode()
    return dsn


def decode_dsn(dsn: str) -> tuple:
    """Decode the DSN to extract user_id, project_id, and SECRET_KEY."""

    decoded_bytes = base64.urlsafe_b64decode(dsn)
    decoded_string = decoded_bytes.decode()
    user_id, project_id, secret_key = decoded_string.split(":")

    # Optionally, verify the secret_key here if needed
    if secret_key != SECRET_KEY:
        return False, None, "Invalid SECRET_KEY"

    return True, user_id, project_id


def check_client_id_exists(client_id: str, data: dict) -> bool:
    """Check if the given client_id exists in the user data."""
    for user in data["users"]:
        if user["user_id"] == client_id:
            return True
    return False


# Function to check if a project_id exists
def check_project_id_exists(project_id: str, data: dict) -> bool:
    """Check if the given project_id exists in the user data."""

    for _, user_data in data["users"].items():
        for project in user_data["projects"]:
            if project["project_id"] == project_id:
                return True
    return False
