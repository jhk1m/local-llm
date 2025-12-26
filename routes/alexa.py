from __future__ import annotations
import logging
from typing import cast
from datetime import timedelta
from app import services, templates
from fastapi import Request
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse, HTMLResponse
from models.alexa import AlexaAuthRequest
from models.core import OAuthTokenResponse, User
from requests import PreparedRequest
from routes.core import redirect_if_not_logged_in
import config

auth_router = APIRouter(prefix="/oauth/authorization", tags=["Alexa Account Linking"])
frontend_router = APIRouter(prefix="/app/alexa", tags=["Alexa Frontend"])

logger = logging.getLogger(__name__)


@frontend_router.get("/configure", response_class=HTMLResponse, name="configure_alexa")
async def configure_alexa_page(request: Request):
    """
    Renders the page for managing the Alexa skill link.
    """
    logged_in_response = await redirect_if_not_logged_in(request)
    if isinstance(logged_in_response, Response):
        return logged_in_response # Redirects to login if the user isn't authenticated

    user: User = logged_in_response

    # NOTE: You must have an 'alexa_config.html' file in your templates directory
    # for this page to render correctly.
    return templates.TemplateResponse("alexa_config.html", {"request": request, "user": user})


@auth_router.get("/authorize", name="authorize")
async def handle_alexa_authorization_request(request: Request, auth: AlexaAuthRequest = Depends()):
    """
    Step 1 of Alexa OAuth flow.
    Receives the initial request from Amazon, validates it, and redirects
    the user to our login page if they are not already authenticated.
    If they are authenticated, it generates the auth code and redirects back to Amazon.
    """
    logger.debug(f"Alexa /authorize hit with state: {auth.state}")
    logger.debug(f"CLIENT ID FROM YOUR CONFIG: '{config.secrets.ALEXA_CLIENT_ID}'")

    # 1. Validate the incoming request from Amazon
    if auth.client_id != config.secrets.ALEXA_CLIENT_ID:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid client_id")
    if auth.response_type != "code":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported response_type")
    if auth.redirect_uri not in config.secrets.ALEXA_REDIRECT_URI:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="redirect_uri not allowed")

    # 2. Check if user is logged in.
    logged_in_response = await redirect_if_not_logged_in(request)
    if isinstance(logged_in_response, Response):
        # User is NOT logged in. Stash OAuth parameters and redirect.
        request.session["oauth_state"] = auth.state
        # ... (stash other params) ...
        
        # --- MODIFICATION ---
        # Create a standard RedirectResponse object first
        response = RedirectResponse(url=request.url_for('log_in'), status_code=status.HTTP_302_FOUND)
        
        # Add headers to prevent caching
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        
        return response # Return the modified response

    # 3. User IS logged in.
    user: User = logged_in_response
    logger.debug(f"User {user.username} is logged in, generating auth code.")

    # Generate the short-lived authorization code
    code = services.alexa.create_auth_code(
        user, client_id=auth.client_id, redirect_uri=auth.redirect_uri
    )

    # 4. Redirect back to Amazon's `redirect_uri` with the code and state.
    req = PreparedRequest()
    req.prepare_url(auth.redirect_uri, {"code": code, "state": auth.state})
    return RedirectResponse(cast(str, req.url), status_code=status.HTTP_302_FOUND)


@auth_router.post('/token', response_model=OAuthTokenResponse)
async def exchange_code_for_token(
    request: Request,
    grant_type: str = Form(...),
    code: str | None = Form(None),
    refresh_token: str | None = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    redirect_uri: str | None = Form(None),
) -> OAuthTokenResponse:
    """
    Step 2 of Alexa OAuth flow. Exchanges the authorization code for tokens
    and performs full client authentication.
    """
    logger.debug(f"Token exchange request received for grant_type: {grant_type}")
    form_data = await request.form()
    logger.info("--- RAW TOKEN REQUEST FROM ALEXA ---")
    logger.info(f"HEADERS: {dict(request.headers)}")
    logger.info(f"FORM BODY: {form_data}")
    logger.info("--- VALIDATING CLIENT SECRET ---")
    logger.info(f"SECRET FROM ALEXA: '{client_secret}'")
    logger.info(f"SECRET FROM YOUR CONFIG: '{config.secrets.ALEXA_CLIENT_SECRET}'")
    logger.info("------------------------------")
    logger.info("------------------------------------")

    # --- Validate both client_id AND client_secret ---
    if client_id != config.secrets.ALEXA_CLIENT_ID:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    if client_secret != config.secrets.ALEXA_CLIENT_SECRET:
        raise HTTPException(status_code=401, detail="Invalid client_secret")

    if grant_type == "authorization_code":
        if not code or not redirect_uri:
            raise HTTPException(status_code=400, detail="Missing code or redirect_uri")
        
        user = services.alexa.validate_auth_code(code, client_id, redirect_uri)
        if not user:
            raise HTTPException(status_code=400, detail="Invalid or expired authorization code")

        # ... create and return tokens ...
        access = services.token.create_token(user.username)
        refresh = services.token.create_refresh_token(user.username)
        return OAuthTokenResponse(
            access_token=access.access_token,
            token_type="Bearer",
            expires_in=int(timedelta(minutes=config.settings.ACCESS_TOKEN_EXPIRE_MINUTES).total_seconds()),
            refresh_token=refresh.access_token,
        )

    elif grant_type == "refresh_token":
        
        pass

    raise HTTPException(status_code=400, detail="Unsupported grant_type")