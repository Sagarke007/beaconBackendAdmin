"""
HTTP Response handler
"""
from typing import Optional, Any

from fastapi.responses import JSONResponse as fastapi_jsonresponse


class HTTPResponse:
    """
    Class to define the HTTP response
    """

    SUCCESS = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204

    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    NOT_ACCEPTABLE = 405

    SERVER_ERROR = 500

    RESPONSE_CODE_WITH_MESSAGES = {
        SUCCESS: "Success",
        CREATED: "Created",
        ACCEPTED: "Accepted",
        NO_CONTENT: "No Content",
        BAD_REQUEST: "Bad Request",
        UNAUTHORIZED: "You are not authorized to perform this action",
        FORBIDDEN: "You are not allowed to perform this action",
        NOT_FOUND: "The resource you are looking for does not exists",
        NOT_ACCEPTABLE: "The inputs provided are not accepted",
        SERVER_ERROR: "The server has encountered an error and is unable to process your request",
    }

    def success(
            self,
            response_data: Optional[Any] = None,
            response_message: Optional[str] = None,
            response_code: int = SUCCESS,
    ):
        """
        Function returns a successful HTTP Response code with exposing of the data
        """
        if response_message is None:
            response_message = self.RESPONSE_CODE_WITH_MESSAGES[response_code]

        if response_data is not None:
            return self.return_response(
                response_code=response_code,
                response_object=response_data,
                response_message=response_message,
            )
        return self.return_response(
            response_code=response_code, response_message=response_message
        )

    def failed(self, response_message: str = str, response_code: int = BAD_REQUEST):
        """
        Function returns a failure of response code and does not expose any data.
        """
        if response_message is None:
            response_message = self.RESPONSE_CODE_WITH_MESSAGES[response_code]

        return self.return_response(
            response_code=response_code, response_message=response_message
        )

    def return_response(
        self,
        response_object: None = None,
        response_array: None = None,
        response_headers: None = None,
        response_code: int = SUCCESS,
        response_message: None = None,
    ):  # pylint: disable=R0917
        """
        Function to wrap the response and return it in a JSON format
        """

        if response_object is None:
            response_object = {}

        if response_array is None:
            response_array = []

        if response_headers is None:
            response_headers = {}

        if response_message is None:
            response_message = self.RESPONSE_CODE_WITH_MESSAGES[response_code]

        if response_code == self.SUCCESS:
            sender_array = []
            if len(response_object) > 0 and len(response_array) > 0:
                sender_array = [response_object, response_array]
            elif len(response_object) > 0 and len(response_array) == 0:
                sender_array = response_object
            elif len(response_object) == 0 and len(response_array) > 0:
                sender_array = response_array

            sender_array = {
                "code": response_code,
                "message": response_message,
                "response": sender_array,
            }
        else:
            sender_array = {
                "code": response_code,
                "message": response_message,
            }
        return fastapi_jsonresponse(
            content=sender_array, headers=response_headers, status_code=response_code
        )
