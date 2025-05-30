"""
Functions to support all user actions and endpoints using JSON file storage
"""

# Standard library imports
import base64
import datetime
import json
import os
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, List

# Related third-party imports
import bcrypt
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Local application/library imports
from shared.utils import verify_password, hash_password, SECRET_KEY

import root_dir_getter

root_dir_getter.set_root_dir(__file__)


SECURITY = HTTPBearer()

# JSON storage file path
JSON_STORAGE_PATH = Path("login_handler.json")


class UserLoginHandler:
    """
    Class to maintain and let user login using JSON file storage
    """

    def __init__(self):
        self.secret_key = SECRET_KEY
        # self.otp_manager = OTPManager()
        self._initialize_json_storage()

    def _initialize_json_storage(self):
        """Initialize the JSON storage file if it doesn't exist"""
        if not JSON_STORAGE_PATH.exists():
            with open(JSON_STORAGE_PATH, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "users": [],
                    },
                    f,
                )

    def _load_data(self) -> Dict[str, Any]:
        """Load data from JSON file"""
        with open(JSON_STORAGE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_data(self, data: Dict[str, Any]):
        """Save data to JSON file"""
        with open(JSON_STORAGE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _find_user_by_email(
        self, email: str, include_all: bool = True
    ) -> Optional[Dict[str, Any]]:
        """
        Finds a user by their email address in the JSON storage.
        """
        data = self._load_data()
        for user in data["users"]:
            if user["email"].lower() == email.lower():
                if include_all or user.get("is_active", True):
                    return user
        return None

    def _find_user_by_user_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Helper method to find a user by user ID.
        """
        data = self._load_data()
        for user in data["users"]:
            if user["user_id"] == user_id:
                return user
        return None

    def _check_contact_uniqueness(self, phone_number: str) -> Optional[str]:
        """
        Checks if the given phone number is unique in the storage.
        """
        if not phone_number:
            return None

        data = self._load_data()
        for user in data["users"]:
            if user.get("phone_number") == phone_number:
                return user
        return None

    def add_user(
        self,
        first_name: str,
        last_name: str,
        email: str,
        password: str,
        phone_number: Optional[str],
    ) -> str:
        """
        Adds a new user to the system.
        """
        user = self._find_user_by_email(email)
        if user:
            return f"Email '{email}' is already registered."

        if phone_number:
            user_contact = self._check_contact_uniqueness(phone_number)
            if user_contact:
                return f"Phone number '{phone_number}' is already registered."

        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        user_id = str(uuid.uuid4())
        user_details = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "first_name": first_name,
            "last_name": last_name,
            "email": email.strip().lower(),
            "password": hashed_password,
            "phone_number": phone_number,
            "token": "",
            "last_logged_in": "",
            "sign_up_date": datetime.datetime.utcnow().isoformat(),
            "is_active": True,
            "is_validate": False,
        }

        data = self._load_data()
        data["users"].append(user_details)
        self._save_data(data)
        return "Success"

    def authenticate_user(self, email: str, password: str):
        """
        Authenticates a user based on the provided email and password.
        """
        user = self._find_user_by_email(email, include_all=False)
        if user and bcrypt.checkpw(
            password.encode("utf-8"), user.get("password").encode("utf-8")
        ):
            token = jwt.encode(
                {
                    "email": email,
                    "user_id": user.get("user_id"),
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
                },
                self.secret_key,
                algorithm="HS256",
            )

            # Update user in storage
            data = self._load_data()
            for idx, u in enumerate(data["users"]):
                if u["user_id"] == user["user_id"]:
                    data["users"][idx]["token"] = token
                    data["users"][idx][
                        "last_logged_in"
                    ] = datetime.datetime.utcnow().isoformat()
                    self._save_data(data)
                    break

            first_name = user.get("first_name", "")
            last_name = user.get("last_name", "")
            platform_access = user.get("platform_access", "")
            is_verified = user.get("is_verified", False)
            is_auth = user.get("is_auth", 0)

            first_name_encoded = base64.b64encode(first_name.encode()).decode("utf-8")
            last_name_encoded = base64.b64encode(last_name.encode()).decode("utf-8")

            # if is_auth == 0:
            #     otp_token = self.otp_manager.generate_otp(email, otp_type="email")
            #     send_email_verification_mail(email, first_name, otp_token["otp"])

            return (
                token,
                first_name_encoded,
                last_name_encoded,
                platform_access,
                is_verified,
                is_auth,
            )
        return None, "", "", "", "", ""

    async def authenticate_token(
        self, credentials: HTTPAuthorizationCredentials = Depends(SECURITY)
    ):
        """
        Authenticates the JWT token against users stored in JSON file.

        Args:
            credentials: Contains the bearer token from the Authorization header

        Returns:
            Tuple (bool, dict): (True, payload) if valid, raises exception otherwise

        Raises:
            HTTPException: 401 if token is invalid or user not found
        """
        try:
            incoming_token = credentials.credentials

            # Decode and verify the JWT token
            valid, payload = self.decode_jwt_token(incoming_token)
            if not valid:
                raise HTTPException(status_code=401, detail="Invalid token")

            # Get user from JSON storage
            user_id = payload["user_id"]
            data = self._load_data()
            user = next((u for u in data["users"] if u["user_id"] == user_id), None)

            # Verify token matches stored token and user is active
            if not user or user.get("token") != incoming_token:
                raise HTTPException(status_code=401, detail="Invalid token")
            if not user.get("is_active", True):
                raise HTTPException(status_code=403, detail="User account inactive")

            return (True, payload)

        # Fix for E0701: Reorder the except clauses
        except jwt.exceptions.InvalidSignatureError as exc:
            raise HTTPException(
                status_code=401, detail="Token signature invalid"
            ) from exc
        except jwt.exceptions.DecodeError as exc:
            raise HTTPException(status_code=401, detail="Invalid token format") from exc
        except KeyError as exc:
            raise HTTPException(
                status_code=401, detail="Missing required token claims"
            ) from exc

    def decode_jwt_token(self, token: str) -> tuple:
        """
        Args:
            token (str): The JWT token to decode.

        Returns:
            tuple: A tuple indicating if the token is valid and the payload of the token.

        Raises:
            HTTPException: If the token is invalid or cannot be decoded.
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return (True, payload)
        except Exception as exc:
            raise HTTPException(status_code=401, detail="Invalid token") from exc

    def logout_user(self, user_id: str) -> bool:
        """
        Logs out a user by clearing their token.
        """
        data = self._load_data()
        for idx, user in enumerate(data["users"]):
            if user["user_id"] == user_id:
                data["users"][idx]["token"] = ""
                self._save_data(data)
                return True
        return False

    # ... (keep all other methods the same, just replace Cosmos DB operations with JSON file operations)
    # For example, update_user_is_active would look like this:

    def update_user_is_active(self, email: str, is_active: bool) -> bool:
        """
        Update the `is_active` field of a user.
        """
        data = self._load_data()
        for idx, user in enumerate(data["users"]):
            if user["email"].lower() == email.lower():
                data["users"][idx]["is_active"] = is_active
                self._save_data(data)
                return True
        return False

    def update_platform_status(self, email: str, updates: Dict[str, int]) -> bool:
        """
        Updates platform statuses for a user.
        """
        data = self._load_data()
        for idx, user in enumerate(data["users"]):
            if user["email"].lower() == email.lower():
                for platform, status in updates.items():
                    data["users"][idx]["platform_access"][platform] = status
                self._save_data(data)
                return True
        return False

    def get_all_users(self, user_id):
        """
        Fetches all users' basic details except the requesting user.
        """
        try:
            data = self._load_data()
            user_list = [
                {
                    "first_name": user.get("first_name"),
                    "last_name": user.get("last_name"),
                    "email": user.get("email"),
                    "last_log_in": user.get("last_logged_in", ""),
                    "is_active": user.get("is_active", True),
                    "platform_access": user.get("platform_access", ""),
                }
                for user in data["users"]
                if user["user_id"] != user_id
            ]
            # Sort by sign_up_date descending (newest first)
            user_list.sort(key=lambda x: x.get("last_log_in", ""), reverse=True)
            return True, user_list
        except Exception as e:  # pylint: disable=broad-exception
            return False, f"Unable to retrieve users: {str(e)}"

    def verify_and_change_password(
        self, current_password: str, new_password: str, user_id: str
    ) -> tuple:
        """
        Verifies the current password and updates it to the new password if valid.
        """
        try:
            data = self._load_data()
            for idx, user in enumerate(data["users"]):
                if user["user_id"] == user_id:
                    # Verify current password
                    if not verify_password(current_password, user["password"]):
                        return False, "Password is not correct"

                    # Hash the new password
                    hashed_new_password = hash_password(new_password)

                    # Update the user's password
                    data["users"][idx]["password"] = hashed_new_password
                    data["users"][idx]["is_verified"] = False
                    data["users"][idx]["token"] = ""
                    self._save_data(data)
                    return True, "Password successfully changed"

            return False, "User not found"
        except (FileNotFoundError, json.JSONDecodeError) as e:
            return False, f"Unable to retrieve users: {str(e)}"

    def update_reset_request_info(self, email: str, count: int, timestamp: str):
        """
        Updates the count and timestamp for password reset requests.
        """
        data = self._load_data()
        found = False
        for idx, req in enumerate(data["reset_requests"]):
            if req["email"] == email:
                data["reset_requests"][idx]["count"] = count
                data["reset_requests"][idx]["timestamp"] = timestamp
                found = True
                break

        if not found:
            data["reset_requests"].append(
                {"email": email, "count": count, "timestamp": timestamp}
            )

        self._save_data(data)

    def get_reset_request_info(self, email):
        """
        Fetches the reset request information for a given email.
        """
        data = self._load_data()
        for req in data["reset_requests"]:
            if req["email"] == email:
                return req
        return None

    # ... (keep all other methods exactly the same as they don't interact with storage)
    # Methods like send_user_registration_email, google_verification, etc. remain unchanged

    def _find_admin_email(self) -> List[str]:
        """
        Helper method to find admin emails.
        """
        admin_id_json_str = os.getenv("ADMIN_USER_ID")
        if not admin_id_json_str:
            return []

        try:
            admin_ids = json.loads(admin_id_json_str)
            data = self._load_data()
            return [
                user["email"]
                for user in data["users"]
                if user["user_id"] in admin_ids and "email" in user
            ]
        except json.JSONDecodeError:
            return []

    async def authenticate_token_ws(self, token_value: str):
        """
        Validates a token string (e.g., from WebSocket headers).
        """
        try:
            # Example: decode JWT token (adjust based on your actual logic)
            _, payload = self.decode_jwt_token(token_value)

            user_id = payload.get("user_id")
            if not user_id:
                raise ValueError("Invalid token payload")

            return True, payload

            # Fix for E0701: Reorder the except clauses
        except jwt.exceptions.InvalidSignatureError as exc:
            raise HTTPException(
                status_code=401, detail="Token signature invalid"
            ) from exc
        except jwt.exceptions.DecodeError as exc:
            raise HTTPException(status_code=401, detail="Invalid token format") from exc
        except KeyError as exc:
            raise HTTPException(
                status_code=401, detail="Missing required token claims"
            ) from exc
