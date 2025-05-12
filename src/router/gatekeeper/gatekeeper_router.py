from fastapi import APIRouter, Body, HTTPException, Depends
from pathlib import Path
import json

from shared.user_utils import UserLoginHandler
from shared.http_responses import HTTPResponse
from shared.utils import enhance_endpoints_with_fake_data

router = APIRouter()

LOCAL_DIR = Path("../health_data")
LOCAL_DIR.mkdir(parents=True, exist_ok=True)  # Create the folder if it doesn't exist

USER_LOGIN = UserLoginHandler()


@router.post("/upload/send-api-health-data")
async def receive_health_data(payload: dict = Body(...)):
    """
    Receive health data from the API and save it into client_id folder as project_id.json
    """
    client_id = payload.get("client_id")
    project_id = payload.get("project_id")

    if not client_id or not project_id:
        return HTTPResponse().failed(response_message="client_id or project_id missing")

    client_dir = LOCAL_DIR / "api_endpoint" / client_id
    client_dir.mkdir(parents=True, exist_ok=True)

    file_path = client_dir / f"{project_id}.json"

    try:
        with open(file_path, "w") as f:
            json.dump(payload, f, indent=2)

        return HTTPResponse().success(response_message=f"File saved to {file_path}")
    except Exception as e:
        return HTTPResponse().failed(response_message=f"Failed to save file: {str(e)}")


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
        fake_payload = enhance_endpoints_with_fake_data(endpoints)

        return HTTPResponse().success(response_data=fake_payload)
    except Exception as e:
        return HTTPResponse().failed(
            response_message=f"Failed to retrieve health data: {str(e)}"
        )


@router.post("/upload/save-api-response")
async def save_api_response(payload: dict = Body(...)):
    """
    Save or append API response payload to response.json under the client_id folder,
    removing 'client_id', 'project_id', and 'response' keys if present.
    """
    client_id = payload.get("client_id")
    project_id = payload.get("project_id")

    if not client_id or not project_id:
        return HTTPResponse().failed(response_message="client_id or project_id missing")

    client_dir = LOCAL_DIR / "api_log" / client_id
    client_dir.mkdir(parents=True, exist_ok=True)

    file_path = client_dir / f"{project_id}.json"

    try:
        # Clean up payload
        payload.pop("client_id", None)
        payload.pop("project_id", None)

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
