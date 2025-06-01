# routes/auth.py - MODIFIED: /authorize ROUTE REMOVED

from __future__ import annotations

import logging
from typing import Annotated, Optional
from urllib.parse import quote_plus, urlencode

from app import services
from fastapi import APIRouter, Depends, Form, HTTPException, Header, Query, Request, status, Response
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from models.core import RateLimitCategory, Token, User, WhitelistError
from services.auth_token import InvalidTokenError, AuthTokenService
from services.user import UserService, UserIsDisabledError, UserIsNotRegisteredError
from routes.core import get_user_session, router as core_router # core_router refers to routes.core.router

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/oauth/authorization/token')
router = APIRouter(prefix='/oauth/authorization', tags=['Authorization'])

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

user_service = UserService()

UserSession = Annotated[User | None, Depends(get_user_session)]

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    logger.debug('Authorization header: %s', token)
    try:
        username = services.token.get_username_from_token(token)
        _user_in_db = services.user.get_user(username, active_only=False)
        
        if not _user_in_db:
            logger.error('User not found for token: %s', token)
            raise InvalidTokenError()

        logger.debug('User found: %s', _user_in_db.username)
        user = _user_in_db.cast(User)

        if user.disabled:
            logger.warning('Disabled user attempted access: %s', username)
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Account disabled')

        return user

    except InvalidTokenError as e:
        logger.error('Invalid token: %s', str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid credentials',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    
# @auth_router.get("/authorize", name="authorize") # <--- THIS IS THE CRITICAL PART
# async def authorize(
#     request: Request,
#     client_id: str = Query(..., alias="client_id"),
#     redirect_uri: str = Query(..., alias="redirect_uri"),
#     state: str = Query(..., alias="state"),
#     response_type: str = Query("code", alias="response_type"),
#     scope: Optional[str] = Query(None, alias="scope")
# ):
#     logger.debug(f"Authorization request received: client_id={client_id}, redirect_uri={redirect_uri}, state={state}, response_type={response_type}, scope={scope}")

#     if client_id != app_secrets.ALEXA_CLIENT_ID:
#         logger.error(f"Invalid client_id: {client_id}")
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid client_id")

#     allowed_uris = app_secrets.ALEXA_REDIRECT_URI if isinstance(app_secrets.ALEXA_REDIRECT_URI, list) else [app_secrets.ALEXA_REDIRECT_URI]
#     if redirect_uri not in allowed_uris:
#         logger.error(f"Invalid redirect_uri: {redirect_uri}. Allowed: {allowed_uris}")
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid redirect_uri")

#     if response_type != "code":
#         logger.error(f"Unsupported response_type: {response_type}")
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported response_type")

#     request.session["oauth_state"] = state
#     request.session["oauth_redirect_uri"] = redirect_uri
#     request.session["oauth_client_id"] = client_id
#     request.session["oauth_response_type"] = response_type

#     user = await get_user_session(request)

#     if not user:
#         logger.debug("User not logged in, redirecting to login page.")
#         login_url = core_router.url_path_for("log_in")
#         login_url_with_oauth_flag = f"{login_url}?oauth_pending=true"
#         return RedirectResponse(login_url_with_oauth_flag, status_code=status.HTTP_302_FOUND)
#     else:
#         logger.debug(f"User {user.username} already logged in. Generating auth code.")
#         try:
#             auth_code = services.alexa.create_auth_code(user, client_id, redirect_uri)

#             request.session.pop("oauth_state", None)
#             request.session.pop("oauth_redirect_uri", None)
#             request.session.pop("oauth_client_id", None)
#             request.session.pop("oauth_response_type", None)

#             final_redirect_url = f"{redirect_uri}?code={auth_code}&state={state}"
#             logger.debug(f"Redirecting user {user.username} to Alexa: {final_redirect_url}")
#             return RedirectResponse(final_redirect_url, status_code=status.HTTP_302_FOUND)
#         except Exception as e:
#             logger.error(f"Error generating auth code or redirecting: {e}")
#             raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Authorization failed")

@router.post('/token', response_model=Token)
async def log_in_for_access_token(
    request: Request, # Need request to access form data properly if using Form()
    grant_type: str = Form(..., alias="grant_type"),
    code: Optional[str] = Form(None, alias="code"),
    redirect_uri: Optional[str] = Form(None, alias="redirect_uri"),
    client_id: Optional[str] = Form(None, alias="client_id"),
    username: Optional[str] = Form(None, alias="username"),
    password: Optional[str] = Form(None, alias="password"),
    alexa_user_id_header: str = Header(None, alias="X-Alexa-UserId"),
) -> Token:
    logger.debug(f"Token exchange request received. Grant Type: {grant_type}")

    if grant_type == "authorization_code":
        if not code or not client_id or not redirect_uri:
            logger.error("Missing required parameters for authorization_code grant.")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing required parameters for authorization_code grant.")

        logger.debug(f"Attempting to validate auth code: {code} for client {client_id} and redirect {redirect_uri}")
        try:
            user = services.alexa.validate_auth_code(code, client_id, redirect_uri)
            if not user:
                logger.error("Invalid or expired authorization code after validation attempt.")
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired authorization code.")
        except Exception as e:
            logger.error(f"Auth code validation failed in token endpoint: {e}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired authorization code.")

        if alexa_user_id_header and not user.alexa_linking.alexa_user_id:
            services.alexa.link_user(user, alexa_user_id_header)

        access_token_obj = services.token.create_token(user.username)
        logger.debug(f"Successfully issued access token for user {user.username} via auth code grant.")
        return access_token_obj

    elif grant_type == "password":
        if not username or not password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing username or password for password grant.")
        try:
            user: User = services.user.get_authenticated_user(username, password)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail='Incorrect username or password',
                    headers={'WWW-Authenticate': 'Bearer'},
                )
            
            if alexa_user_id_header and not user.alexa_linking.alexa_user_id:
                services.alexa.link_user(user, alexa_user_id_header)

            logger.debug(f"Successfully issued access token for user {user.username} via password grant.")
            return services.token.create_token(user.username)

        except UserIsNotRegisteredError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='User has not completed registration',
                headers={'WWW-Authenticate': 'Bearer'},
            )
        except UserIsDisabledError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='User is disabled and must request a password reset',
                headers={'WWW-Authenticate': 'Bearer'},
            )
        except WhitelistError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='User is not whitelisted on this server',
                headers={'WWW-Authenticate': 'Bearer'},
            )
        except Exception as e:
            logger.error(f"Error during password grant login: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An internal server error occurred.",
                headers={'WWW-Authenticate': 'Bearer'},
            )
    else:
        logger.error(f"Unsupported grant_type: {grant_type}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported grant_type.")
    
@router.get('/me', response_model=User)
@services.rate_limit.limit(RateLimitCategory.read)
async def get_logged_in_user(
    current_user: User = Depends(get_current_user),
) -> User:
    return current_user