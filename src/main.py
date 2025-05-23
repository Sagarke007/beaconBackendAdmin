"""
Qna Main Application File:

 Agent mira questions will be asked by Agent_QnA. The API endpoint with
preferences and other pages will take care of the questions
"""

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from starlette.responses import JSONResponse

from router.gatekeeper import gatekeeper_router
from router.user import user_router
from router.insights import insights_router

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

    # Customize 401 Unauthorized error
    if exc.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN):
        return JSONResponse(
            content={
                "code": status.HTTP_401_UNAUTHORIZED,
                "message": "You are not authorized or Session expired.Please log in again.",
                "response": [],
            }
        )
    # Default for all other HTTP exceptions
    return JSONResponse(
        content={"code": exc.status_code, "message": exc.detail, "response": []}
    )


app.include_router(gatekeeper_router.router, prefix="/gatekeeper")
app.include_router(user_router.router, prefix="/user")
app.include_router(insights_router.router, prefix="/insights")


@app.get("/")
async def read_root():
    """app root checking function

    Returns:
        _type_: _description_
    """
    return {"message": "Welcome to the  Beacon Backend FastAPI app!"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=3999)  # Running on a different port
