"""
Qna Main Application File:

Agent mira questions will be asked by Agent_QnA. The API endpoint with
preferences and other pages will take care of the questions.
"""

import asyncio

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi import WebSocket, WebSocketDisconnect
import json
from starlette.responses import JSONResponse

from router.gatekeeper import gatekeeper_router
from router.user import user_router
from router.insights import insights_router
from router.gatekeeper.gatekeeper_router import USER_LOGIN
from shared.insight_utils import LOCAL_DIR

app = FastAPI()

# Middleware: CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3999",
        "http://localhost:5173",
        "http://dev.viewcurry.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Exception handler for HTTP exceptions
@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException):
    """
    Handle HTTP exceptions globally.
    This function is called whenever an HTTPException is raised in the application.
    """
    if exc.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN):
        return JSONResponse(
            content={
                "code": status.HTTP_401_UNAUTHORIZED,
                "message": "You are not authorized or Session expired. Please log in again.",
                "response": [],
            }
        )
    return JSONResponse(
        content={"code": exc.status_code, "message": exc.detail, "response": []}
    )


app.include_router(gatekeeper_router.router, prefix="/gatekeeper")
app.include_router(user_router.router, prefix="/user")
app.include_router(insights_router.router, prefix="/insights")


@app.get("/")
async def read_root():
    """
    App root checking function.

    Returns:
        dict: A welcome message for the FastAPI app.
    """
    return {"message": "Welcome to the Beacon Backend FastAPI app!"}


@app.websocket("/ws/")
async def websocket_logs(websocket: WebSocket):
    """
    WebSocket endpoint to stream logs.

    Args:
        websocket (WebSocket): The WebSocket connection.

    Raises:
        WebSocketDisconnect: Raised when the WebSocket disconnects.
    """
    await websocket.accept()

    try:
        data = await websocket.receive_text()
        data_json = json.loads(data)

        token = data_json.get("token")
        project_id = data_json.get("project_id")

        if not token or not project_id:
            await websocket.send_json({"error": "token and project_id required"})
            await websocket.close()
            return

        _, user_info_data = await USER_LOGIN.authenticate_token_ws(token)
        user_id = user_info_data["user_id"]

        file_path = LOCAL_DIR / "api_log" / user_id / f"{project_id}.json"
        if not file_path.exists():
            await websocket.send_json({"error": "Log file not found."})
            await websocket.close()
            return

        last_read_index = 0
        while True:
            with open(file_path, "r", encoding="utf-8") as f:
                log_entries = json.load(f)

            new_entries = log_entries[last_read_index:]
            filtered_logs = [
                entry
                for entry in new_entries
                if 200 <= int(entry.get("status_code", 0)) <= 600
            ]

            for entry in filtered_logs:
                await websocket.send_json(entry)

            last_read_index = len(log_entries)
            await asyncio.sleep(2)

    except WebSocketDisconnect:
        print("WebSocket disconnected")
    except json.JSONDecodeError as jde:
        await websocket.send_json({"error": f"JSON decode error: {str(jde)}"})
        await websocket.close()
    except FileNotFoundError as fnfe:
        await websocket.send_json({"error": f"File not found: {str(fnfe)}"})
        await websocket.close()
    except Exception as e:
        await websocket.send_json({"error": str(e)})
        await websocket.close()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=3999)
