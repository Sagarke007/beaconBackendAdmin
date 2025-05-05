

from fastapi import APIRouter, Body, HTTPException
from pathlib import Path
import json

from shared.http_responses import HTTPResponse


router = APIRouter()

LOCAL_DIR = Path("../health_data")

LOCAL_DIR.mkdir(parents=True, exist_ok=True)  # Create the folder if it doesn't exist


@router.post("/upload/send-api-health-data")
async def receive_health_data(payload: dict = Body(...)):
    """
    Receive health data from the API and save it to a local file.
    :param payload: dict containing health data
    :return: True if the data is saved successfully, False otherwise
    """
    client = payload.get("client_id")
    project = payload.get("project_id")

    if not client or not project:
        return {"status": "error", "message": "client_id or project_id missing"}

    # Optional: Include a timestamp in the filename to avoid overwriting
    filename = f"{project}_{client}_api_health.json"
    file_path = LOCAL_DIR / filename

    try:
        with open(file_path, "w") as f:
            json.dump(payload, f, indent=2)

        return HTTPResponse().success(response_message=f"File saved to {file_path}")

    except Exception as e:
        return HTTPResponse().failed(response_message= str(e))


@router.get("/retrieve-file/{project_id}/{client_id}")
async def get_health_data(
        project_id: str,
        client_id: str
):
    """
    Retrieve health data for a specific project and client.

    Args:
        project_id: The project identifier
        client_id: The client identifier

    Returns:
        dict: The stored health data
    """
    try:
        filename = f"{project_id}_{client_id}_api_health.json"
        file_path = LOCAL_DIR / filename

        if not file_path.exists():
            raise HTTPException(
                status_code=404,
                detail={
                    "status": "error",
                    "message": "Health data not found for the given project and client"
                }
            )

        with open(file_path, "r") as f:
            data = json.load(f)
        endpoints = data["endpoints"]
        return HTTPResponse().success (response_data=endpoints)

    except Exception as e:
        return HTTPResponse().failed(response_message= f"Failed to retrieve health data: {str(e)}")



