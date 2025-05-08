"""
API Endpoints related to user actions
"""

import os

import json
from fastapi import APIRouter, Depends

import root_dir_getter  # pylint: disable=unused-import


root_dir_getter.set_root_dir(__file__)  # pylint: disable=wrong-import-position

from router.user.models import (  # pylint: disable=unused-import
    UserRegistration,
    PlatformUpdatePayload,
    UserAccessUpdatePayload,
    LoginRequest,
    TokenPayload,
    ChangePasswordRequest,
    UserEmailRequest,
)

from shared.http_responses import HTTPResponse  # pylint: disable=unused-import
from shared.user_utils import UserLoginHandler  # pylint: disable=unused-import
from shared.utils import (
    decode_from_base64,
    validate_password,
)  # pylint: disable=unused-import

router = APIRouter()
USER_LOGIN = UserLoginHandler()
# Initialize manager


@router.post("/signup")
async def user_signup(request: UserRegistration):
    """
    User registering

    Args:
        request (UserRegistration): Registration payload

    Returns:
        _type_: HTTP response
    """
    result = USER_LOGIN.add_user(
        request.first_name,
        request.last_name,
        request.email_address,
        request.password,
        request.phone_number,
    )

    if result == "Success":
        return HTTPResponse().success(response_message="User registered successfully.")
    return HTTPResponse().failed(response_message=result)


@router.post("/login", description="User logging in through local credentials")
async def login_user_with_credentials(payload: LoginRequest):
    """
    User wants to login through their astranest credentails
    """
    # To Do implement login here
    (token, first_name, last_name, platform_access, is_verified, is_auth) = (
        USER_LOGIN.authenticate_user(payload.username, payload.password)
    )
    if token is not None:
        validate_token, user_data = USER_LOGIN.decode_jwt_token(token)
        # admin_user_id = os.getenv("ADMIN_USER_ID")
        admin_user_ids = json.loads(os.getenv("ADMIN_USER_ID", "[]"))

        if user_data["user_id"] in admin_user_ids:
            is_admin = 1
        else:
            is_admin = 0

        if validate_token:
            return HTTPResponse().success(
                response_data={
                    "token": token,
                    "firstName": first_name,
                    "lastName": last_name,
                    "is_admin": is_admin,
                    "platform_access": platform_access,
                    "is_verified": is_verified,
                    "is_auth": is_auth,
                }
            )
        return HTTPResponse().failed(
            response_message="Token validation failed. Please try again."
        )
    return HTTPResponse().failed(
        response_message="Incorrect email or password. Please try again."
    )


@router.post(
    "/set-user-status", description="User logging in through local credentials"
)
async def deactivate_user(
    request: UserAccessUpdatePayload,
    user_info: str = Depends(USER_LOGIN.authenticate_token),
):
    """

    :param request: status
    :param user_info: user_id
    :return: set status of user
    """
    try:
        _, user_info_data = user_info
        user_id = user_info_data["user_id"]
        email = request.email
        is_active = request.is_active
        # Get the admin user ID from environment variables
        admin_user_ids = json.loads(os.getenv("ADMIN_USER_ID", "[]"))
        if user_id not in admin_user_ids:
            return HTTPResponse().failed("Access denied. Admins only")

        status = USER_LOGIN.update_user_is_active(email=email, is_active=is_active)
        if status:
            return HTTPResponse().success("user updated successfully")
        return HTTPResponse().failed("user  not updated successfully")

    except:  # pylint: disable=bare-except
        return HTTPResponse().failed("Failed to update platform statuses")


@router.post("/login/google")
async def google_login(request: TokenPayload):
    """Google SSO login callback API"""

    # Extract the token from the payload
    google_token = request.google_token
    try:
        # Call the callback method
        status, result = USER_LOGIN.google_verification(google_token)
        if status:
            # Unpack successful response
            (
                token,
                first_name,
                last_name,
                platform_access,
            ) = result
            return HTTPResponse().success(
                response_data={
                    "token": token,
                    "firstName": first_name,
                    "lastName": last_name,
                    "platform_access": platform_access,
                }
            )
        return HTTPResponse().failed(response_message=result)
        # Return the response from the callback method
    except Exception as e:  # pylint: disable=broad-exception-caught
        return HTTPResponse().failed(
            response_message=f"Error during Google callback: {str(e)}"
        )


@router.get("/user-access-list", description="Get all user name")
def user_access_list(user_info: str = Depends(USER_LOGIN.authenticate_token)):
    """
    To get all user access list
    """
    try:
        _, user_info_data = user_info
        user_id = user_info_data["user_id"]
        # Get the admin user ID from environment variables
        admin_user_ids = json.loads(os.getenv("ADMIN_USER_ID", "[]"))
        if user_id in admin_user_ids:

            status, response = USER_LOGIN.get_all_users(user_id=user_id)
            if status:
                return HTTPResponse().success(response_data=response)

            return HTTPResponse().failed(
                response_code=HTTPResponse().SERVER_ERROR, response_message=response
            )
        return HTTPResponse().failed(
            response_code=HTTPResponse().SERVER_ERROR,
            response_message="Unauthorized action: You do not have "
            "permission to modify user access.",
        )
    except Exception as err:  # pylint: disable=broad-exception-caught
        return HTTPResponse().failed(
            response_code=HTTPResponse().SERVER_ERROR, response_message=str(err)
        )


# Define the route
@router.post("/update-platforms", description="Update platform statuses for a user")
async def update_platform_status(
    request: PlatformUpdatePayload,  # JSON body payload
    user_info: dict = Depends(
        USER_LOGIN.authenticate_token
    ),  # Dependency for authentication
):
    """
    Updates platform statuses based on the provided email and update fields.
    """
    try:
        # Authenticate user and check admin privileges]
        _, user_info_data = user_info
        user_id = user_info_data["user_id"]
        admin_user_ids = json.loads(os.getenv("ADMIN_USER_ID", "[]"))

        if user_id not in admin_user_ids:
            return HTTPResponse().failed("Access denied. Admins only")

        # Extract email and platform updates
        email = request.email
        # Check for which platform has been provided in the payload
        updates = {}

        if request.IsMarketSavant is not None:
            updates["IsMarketSavant"] = request.IsMarketSavant

        if request.IsOfferSavant is not None:
            updates["IsOfferSavant"] = request.IsOfferSavant

        if request.IsContract is not None:
            updates["IsContract"] = request.IsContract
        # Filter out None values
        valid_updates = {
            key: value for key, value in updates.items() if value is not None
        }

        # Update the platform statuses if valid updates exist
        if valid_updates:
            update_status = USER_LOGIN.update_platform_status(
                email=email, updates=valid_updates
            )
            if update_status:
                return HTTPResponse().success("Platform statuses updated successfully")
            return HTTPResponse().success("Failed to update platform statuses")

        return HTTPResponse().failed("No valid updates provided")

    except:  # pylint: disable=bare-except
        return HTTPResponse().failed("Failed to update platform statuses")


@router.post("/logout", tags=["logout"])
async def logout_user(user_info: str = Depends(USER_LOGIN.authenticate_token)):
    """Ensures user logout

    Args:
        user_info (str, optional):
        _description_. Defaults to Depends(USER_LOGIN.authenticate_token).
    Returns:
        _type_: _description_
    """
    valid, user_info = user_info
    if valid and USER_LOGIN.logout_user(user_info["user_id"]):
        return HTTPResponse().success()
    return HTTPResponse().failed(response_code=401)


@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    user_info: str = Depends(USER_LOGIN.authenticate_token),
):
    """
    Endpoint to change the user's password.

    Args:
        request (ChangePasswordRequest): Request body containing current and new passwords.
        user_info (str): User information retrieved via token authentication.

    Returns:
        dict: A success message or an error message.
    """
    try:
        # Decode Base64-encoded passwords
        current_password = decode_from_base64(request.current_password)
        new_password = decode_from_base64(request.new_password)
        confirm_password = decode_from_base64(request.confirm_password)
        # Validate the password complexity
        validate_password(new_password)
        if new_password == current_password:
            return HTTPResponse().failed(
                response_message="Current password and new password can not be same."
            )
        # Ensure new_password and confirm_password match
        if new_password != confirm_password:
            return HTTPResponse().failed(
                response_message="New password and confirm password do not match."
            )

        _, user_info = user_info
        # Call the method to verify the current password and change it
        status, message = USER_LOGIN.verify_and_change_password(
            current_password, new_password, user_info["user_id"]
        )
        if status:
            return HTTPResponse().success(response_data=message)
        return HTTPResponse().failed(response_message=message)
    except ValueError as e:
        return HTTPResponse().failed(response_message=str(e))
    except:  # pylint: disable=bare-except
        return HTTPResponse().failed(
            response_message="An error occurred while changing the password. Please try again."
        )


@router.post("/forgot-password")
async def forgot_password(request: UserEmailRequest):
    """
    Handles password reset requests by sending a reset link to the user's email.

    Args:
        email (str): The email of the user requesting a password reset.

    Returns:
        dict: Success message.
    """
    # Fetch user by email (pseudo-code)
    try:
        email = decode_from_base64(request.email)
        if "@" not in email or "." not in email:
            return HTTPResponse().failed(
                response_message="Email is not a valid email address"
            )

        status, message = USER_LOGIN.request_password_reset(email)
        if not status:
            return HTTPResponse().failed(response_message=message)
        return HTTPResponse().success(response_data=message)
    except:  # pylint: disable=bare-except
        # Return a generic error response
        return HTTPResponse().failed(
            response_message="An error occurred while resetting the password. Please try again."
        )


@router.post("/reset-password/{otp}")
async def reset_password(request: UserEmailRequest, otp: str):
    """
    Resets the user's password using a reset token.
    ResetPasswordRequest : Model to verify the token and password
    Returns:
        dict: Success or failure response.
    """
    try:
        email = decode_from_base64(request.email)
        if "@" not in email or "." not in email:
            return HTTPResponse().failed(
                response_message="Email is not a valid email address"
            )

        # decode the otp
        otp = decode_from_base64(otp)
        # Validate the reset token
        status, message = USER_LOGIN.validate_password_reset_token(email, otp)

        if not status:
            return HTTPResponse().failed(response_message=message)

        return HTTPResponse().success(response_data=message)

    except:  # pylint: disable=bare-except
        return HTTPResponse().failed(
            response_message="An error occurred while resetting the password. Please try again."
        )


@router.post("/resend-otp")
async def resend_otp(request: UserEmailRequest):
    """
    Endpoint to resend OTP to the user.
    """
    try:
        # Resend OTP to the user
        email = decode_from_base64(request.email)
        if "@" not in email or "." not in email:
            return HTTPResponse().failed(
                response_message="Email is not a valid email address"
            )
        status, message = USER_LOGIN.resend_otp_validation(email)
        if not status:
            return HTTPResponse().failed(response_message=message)

        return HTTPResponse().success(response_data=message)

    except:  # pylint: disable=bare-except
        return HTTPResponse().failed(
            response_message="An error occurred while resending the verification code. Please try again."
        )


@router.post("/validate-identity/{otp}")
async def validate_identity(request: UserEmailRequest, otp: str):
    """
    Resets the user's password using a reset token.
    ResetPasswordRequest : Model to verify the token and password
    Returns:
        dict: Success or failure response.
    """
    try:
        email = decode_from_base64(request.email)
        if "@" not in email or "." not in email:
            return HTTPResponse().failed(
                response_message="Email is not a valid email address"
            )

        # decode the otp
        otp = decode_from_base64(otp)
        # Validate the reset token
        status, message = USER_LOGIN.validate_email(email, otp)

        if not status:
            return HTTPResponse().failed(response_message=message)

        return HTTPResponse().success(response_data=message)

    except:  # pylint: disable=bare-except
        return HTTPResponse().failed(
            response_message="An error occurred while resetting the password. Please try again."
        )


