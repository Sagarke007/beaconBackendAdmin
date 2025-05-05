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


from dotenv import load_dotenv

load_dotenv("../.env")

SECRET_KEY = os.environ.get("USER_AUTH_SECRET_KEY")



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