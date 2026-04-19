import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.models.endpoint_model import (
    EndpointConfig,
    EndpointConfigCreate,
    EndpointConfigUpdate,
    EndpointListItem,
    UserApiKeyPayload,
    UserLoginPayload,
    UserLoginResponse,
    UserRegisterPayload,
)
from backend.services.registry_service import (
    authenticate_user,
    delete_endpoint,
    get_user_api_key,
    list_endpoints,
    register_endpoint,
    register_user,
    update_endpoint,
    upsert_user_api_key,
    verify_password_for_user,
    verify_token,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Endpoint Management"])
_bearer = HTTPBearer()


# ── Auth helpers ───────────────────────────────────────────────────────────────

def _require_token(username: str, credentials: HTTPAuthorizationCredentials) -> None:
    """Raise 401 if the bearer token doesn't match the stored token for username."""
    if not verify_token(username, credentials.credentials):
        raise HTTPException(status_code=401, detail="Invalid or expired token.")


# ── User registration & login ──────────────────────────────────────────────────

@router.post("/users/register", status_code=201, tags=["Users"])
def register(payload: UserRegisterPayload):
    """
    Create a new user account.

    - `username` — unique, case-insensitive
    - `password` — minimum 8 characters (stored as bcrypt hash, never in plaintext)
    - `gemini_api_key` — optional; can be set later via `POST /users/api-key`
    """
    try:
        register_user(
            username=payload.username,
            password=payload.password,
            gemini_api_key=payload.gemini_api_key,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"message": f"User '{payload.username.lower()}' registered successfully."}


@router.post("/users/login", response_model=UserLoginResponse, tags=["Users"])
def login(payload: UserLoginPayload):
    """
    Authenticate and receive a session token.

    Pass the returned `token` as a **Bearer token** in the `Authorization` header
    for all protected routes.
    """
    token = authenticate_user(payload.username, payload.password)
    if not token:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    return UserLoginResponse(username=payload.username.lower(), token=token)


# ── User API key management (protected) ───────────────────────────────────────

@router.post("/users/api-key", status_code=204, tags=["Users"])
def set_user_api_key(
    payload: UserApiKeyPayload,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
):
    """
    Store or update a Gemini API key for a username.

    Requires a valid **Bearer token** (obtained from `POST /users/login`).
    The password in the body provides an extra confirmation step.
    """
    _require_token(payload.username, credentials)
    if not verify_password_for_user(payload.username, payload.password):
        raise HTTPException(status_code=403, detail="Password confirmation failed.")
    upsert_user_api_key(payload.username, payload.gemini_api_key)


# ── Endpoint registration & management ────────────────────────────────────────

@router.post("/register", response_model=EndpointConfig, status_code=201)
def register_ep(
    payload: EndpointConfigCreate,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
):
    """
    Register a new dynamic AI endpoint. Requires a valid Bearer token for `username`.

    `output_schema` must be a valid JSON Schema object, e.g.:

    ```json
    {
      "title": "SentimentResult",
      "type": "object",
      "required": ["sentiment", "confidence"],
      "properties": {
        "sentiment": {"type": "string", "enum": ["positive", "negative", "neutral"]},
        "confidence": {"type": "number"}
      }
    }
    ```
    """
    _require_token(payload.username, credentials)

    if not payload.endpoint_name.replace("_", "").replace("-", "").isalnum():
        raise HTTPException(
            status_code=422,
            detail="endpoint_name must be alphanumeric (underscores and hyphens allowed).",
        )
    try:
        return register_endpoint(payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.patch("/{username}/{endpoint_name}", response_model=EndpointConfig, tags=["Endpoint Management"])
def edit_endpoint(
    username: str,
    endpoint_name: str,
    patch: EndpointConfigUpdate,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
):
    """
    Partially update a registered endpoint. Only the fields you include are changed.

    Requires a valid Bearer token for `username`.

    Example — update just the prompt:
    ```json
    { "ai_prompt": "You are now a strict JSON formatter." }
    ```
    """
    _require_token(username, credentials)
    updated = update_endpoint(username, endpoint_name, patch)
    if not updated:
        raise HTTPException(
            status_code=404,
            detail=f"No endpoint found at /{username}/{endpoint_name}.",
        )
    return updated


@router.get("/list", response_model=List[EndpointListItem])
def list_all(username: Optional[str] = Query(default=None, description="Filter by username")):
    """List all registered endpoints, optionally filtered by username."""
    configs = list_endpoints(username=username)
    return [
        EndpointListItem(
            endpoint_name=c.endpoint_name,
            username=c.username,
            description=c.description,
            input_fields=[f.name for f in c.input_fields],
            output_schema=c.output_schema,
            created_at=c.created_at,
        )
        for c in configs
    ]


@router.delete("/{username}/{endpoint_name}", status_code=204)
def delete(
    username: str,
    endpoint_name: str,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
):
    """Delete a registered dynamic endpoint. Requires a valid Bearer token for `username`."""
    _require_token(username, credentials)
    if not delete_endpoint(username, endpoint_name):
        raise HTTPException(status_code=404, detail="Endpoint not found.")