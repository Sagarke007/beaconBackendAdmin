from fastapi import APIRouter, Body, HTTPException, Depends
from pathlib import Path
import json

from shared.user_utils import UserLoginHandler
from shared.http_responses import HTTPResponse
from shared.utils import enhance_endpoints_with_fake_data

from router.gatekeeper.model import SchemaRequest

from shared.database import read_data
from shared.utils import check_project_id_exists, decode_dsn, check_client_id_exists

router = APIRouter()

LOCAL_DIR = Path("../health_data")
LOCAL_DIR.mkdir(parents=True, exist_ok=True)  # Create the folder if it doesn't exist

USER_LOGIN = UserLoginHandler()


@router.post("/upload/send-api-health-data")
async def receive_health_data(payload: dict = Body(...)):
    """
    Receive health data from the API and save it into client_id folder as project_id.json
    """
    dsn = payload.get("dsn")
    # Decode the DSN and extract user_id, project_id
    success, user_id, project_id = decode_dsn(dsn)
    if not success:
        return HTTPResponse().failed(response_message="Invalid DSN")
    # Check if the user_id exists in login_handler.json
    user_data = read_data("login_handler.json")
    exits = check_client_id_exists(user_id, user_data)

    if not exits:
        return HTTPResponse().failed(response_message="Unauthorized access")
    # Check if the project_id exists in projects.json
    project_data = read_data("projects.json")
    exists = check_project_id_exists(project_id, project_data)
    if not exists:
        return HTTPResponse().failed(response_message="Project ID does not exist")

    user_dir = LOCAL_DIR / "api_endpoint" / user_id

    user_dir.mkdir(parents=True, exist_ok=True)

    file_path = user_dir / f"{project_id}.json"

    try:
        payload.pop("DSN", None)
        with open(file_path, "w") as f:
            json.dump(payload, f, indent=2)

        return HTTPResponse().success(response_message=f"File saved to {file_path}")
    except Exception as e:
        return HTTPResponse().failed(response_message=f"Failed to save file: {str(e)}")


@router.post("/upload/save-api-response")
async def save_api_response(payload: dict = Body(...)):
    """
    Save or append API response payload to response.json under the client_id folder,
    removing 'client_id', 'project_id', and 'response' keys if present.
    """
    dsn = payload.get("dsn")
    # Decode the DSN and extract user_id, project_id
    success, user_id, project_id = decode_dsn(dsn)
    if not success:
        return HTTPResponse().failed(response_message="Invalid DSN")
    # Check if the user_id exists in login_handler.json
    user_data = read_data("login_handler.json")
    exits = check_client_id_exists(user_id, user_data)

    if not exits:
        return HTTPResponse().failed(response_message="Unauthorized access")
    # Check if the project_id exists in projects.json
    project_data = read_data("projects.json")
    exists = check_project_id_exists(project_id, project_data)
    if not exists:
        return HTTPResponse().failed(response_message="Project ID does not exist")

    user_dir = LOCAL_DIR / "api_log" / user_id
    user_dir.mkdir(parents=True, exist_ok=True)

    file_path = user_dir / f"{project_id}.json"

    try:
        # Clean up payload
        payload.pop("DSN", None)
        # Unwrap 'response' key if present
        if isinstance(payload, dict) and "response" in payload:
            payload = payload["response"]

        # Load existing data
        if file_path.exists():
            with open(file_path, "r") as f:
                data = json.load(f)
                if not isinstance(data, list):
                    data = [data]
        else:
            data = []

        data.append(payload)

        with open(file_path, "w") as f:
            json.dump(data, f, indent=2)

        return HTTPResponse().success(response_message=f"Response saved to {file_path}")
    except Exception as e:
        return HTTPResponse().failed(
            response_message=f"Failed to save response: {str(e)}"
        )


@router.get("/retrieve-file/{project_id}")
async def get_health_data(
    project_id: str, user_info: str = Depends(USER_LOGIN.authenticate_token)
):
    """
    Retrieve health data stored inside client_id/project_id.json
    """
    try:
        _, user_info_data = user_info
        user_id = user_info_data["user_id"]
        file_path = LOCAL_DIR / "api_endpoint" / user_id / f"{project_id}.json"
        if not file_path.exists():
            return HTTPResponse().failed(
                response_message={
                    "message": "Health data not found for the given project and client"
                }
            )

        with open(file_path, "r") as f:
            data = json.load(f)
        endpoints = data.get("endpoints", {})
        return HTTPResponse().success(response_data=endpoints)
    except Exception as e:
        return HTTPResponse().failed(
            response_message=f"Failed to retrieve health data: {str(e)}"
        )


@router.post("/schema/generate-data")
async def generate_data(req: SchemaRequest):
    """
    Generate fake data based on provided schema

    Example Request Body:
    {
        "schema_config": {
            "first_name": "string",
            "last_name": "string",
            "email": "string",
            "age": "number",
            "is_active": "boolean"
        }
    }
    """
    try:
        if not req.schema_config:
            raise HTTPException(status_code=400, detail="Schema cannot be empty")

        data = enhance_endpoints_with_fake_data(req.schema_config)
        return HTTPResponse().success(response_data=data)
    except Exception as e:
        return HTTPResponse().failed(
            response_message=f"Failed to generate data: {str(e)}"
        )
