import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

logger = logging.getLogger("ddos-detector")

class LogRequestResponseMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        try:
            if request.method in ("POST", "PUT", "PATCH"):
                request_body = await request.body()
            else:
                request_body = b""
        except Exception as e:
            logger.warning(f"Failed to read request body: {e}")
            request_body = b""

        logger.info(f"Request: method={request.method} url={request.url} headers={dict(request.headers)} body={request_body.decode('utf-8', errors='ignore')}")

        response = await call_next(request)

        response_body = b""
        async for chunk in response.body_iterator:
            response_body += chunk

        logger.info(f"Response: status_code={response.status_code} body={response_body.decode('utf-8', errors='ignore')}")

        return Response(content=response_body, status_code=response.status_code, headers=dict(response.headers), media_type=response.media_type)

def log_request_response(app):
    return LogRequestResponseMiddleware(app)
