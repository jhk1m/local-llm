from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any
from typing import cast
from urllib.parse import urlencode

import config

from app import app
from app import templates
from app import services

from botocore.exceptions import ClientError
from fastapi import APIRouter
from fastapi import BackgroundTasks
from fastapi import Depends
from fastapi import Form
from fastapi import Query
from fastapi import Request
from fastapi import Response
from fastapi import status
from fastapi.responses import HTMLResponse
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from models.core import Token
from models.core import User
from models.core import WhitelistError
from models.email import PasswordResetEmail
from models.email import RegistrationEmail
from requests import PreparedRequest
from services.auth_token import InvalidTokenError
from services.user import UserAlreadyExistsError
from services.user import UserIsDisabledError
from services.user import UserIsNotRegisteredError


router = APIRouter(prefix='/app', tags=['Application'])

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


async def get_user_session(request: Request) -> User | None:
    """Get logged in user from session cookie"""
    session_token = request.cookies.get('session_token')
    
    if not session_token:
        return None
        
    if not services.token.validate_session(session_token):
        return None
    try: 
        username = services.token.get_username_from_token(session_token)
    except InvalidTokenError:
        return None
    
    _user_in_db = services.user.get_user(username)
    if not _user_in_db:
        return None
    
    return _user_in_db.cast(User)


async def redirect_if_not_logged_in(
    request: Request, redirect_path: str | None = None, params: dict | None = None,
) -> Response | User:
    """Return a user if logged in, or a redirect response"""

    if params is None:
        params = {}

    response = RedirectResponse(router.url_path_for('log_in'), status_code=status.HTTP_302_FOUND)
    user = await get_user_session(request)

    if user:
        return user

    if redirect_path:
        route_url = str(request.base_url)[:-1] + redirect_path
        req = PreparedRequest()
        req.prepare_url(route_url, params)
        redirect_url = cast(str, req.url)

        response.set_cookie(key='redirect', value=redirect_url, httponly=True)

    return response


async def set_user_session(response: Response, token: Token) -> None:
    """Add the access token cookie"""
    response.set_cookie(
        key='access_token',
        value=token.access_token, httponly=True,
    )


async def clear_user_session(response: Response) -> None:
    """Remove the access token cookie"""
    response.delete_cookie(key='access_token')


def send_registration_email(registration_url: str, username: str, email: str):
    try:
        msg = RegistrationEmail()
        services.smtp.send(
            msg.message(
                username, email, registration_url=registration_url,
            ),
        )

    except Exception as e:
        logging.error(
            f'Unhandled exception when trying to send a new user ({username}) their registration email',
        )
        logging.error(f'{type(e).__name__}: {e}')


def send_password_reset_email(password_reset_url: str, username: str, email: str):
    try:
        msg = PasswordResetEmail()
        services.smtp.send(
            msg.message(
                username, email, password_reset_url=password_reset_url,
            ),
        )
    except Exception as e:
        logging.error(
            f'Unhandled exception when trying to send a user ({username}) their password reset email',
        )
        logging.error(f'{type(e).__name__}: {e}')


@router.get('/alexa-link', response_class=HTMLResponse)
async def alexa_link(request: Request, code: str, state: str):
    """Render the Alexa account linking completion page."""
    docs_url = str(request.base_url)[:-1] + request.app.docs_url if request.app.docs_url else None
    user = await get_user_session(request)

    return templates.TemplateResponse(
        'alexa_link.html',
        {'request': request, 'user': user, 'docs_url': docs_url, 'code': code, 'state': state},
    )


@router.get('', response_class=HTMLResponse, name="home")
async def home(request: Request, response: Response):
    """Render the home page"""
    docs_url = str(request.base_url)[:-1] + request.app.docs_url if request.app.docs_url else None
    user = await get_user_session(request)
    return templates.TemplateResponse('home.html', {'request': request, 'user': user, 'docs_url': docs_url})


@router.get('/privacy-policy', response_class=HTMLResponse)
async def privacy_policy(request: Request, response: Response):
    user = await get_user_session(request)
    return templates.TemplateResponse('legal.html', context={'request': request, 'user': user})


@router.get('/login', response_class=HTMLResponse, name="log_in")
async def log_in(
    request: Request,
    error: bool = False,
    response_type: str | None = Query(None),
    client_id: str | None = Query(None),
    redirect_uri: str | None = Query(None),
    state: str | None = Query(None),
) -> HTMLResponse | RedirectResponse:
    """Render the login page, saving any pending OAuth details to the session."""
    
    # If this is the start of an Alexa OAuth flow, save the parameters
    if response_type and client_id and redirect_uri and state:
        logger.debug(f"STEP 1 (GET): Received Alexa params. State: {state}, Redirect URI: {redirect_uri}")
        request.session["oauth_state"] = state
        request.session["oauth_redirect_uri"] = redirect_uri
        request.session["oauth_client_id"] = client_id
        request.session["oauth_response_type"] = response_type

    # If already logged in, redirect to home
    if await get_user_session(request):
        return RedirectResponse(router.url_path_for('home'), status_code=status.HTTP_302_FOUND)

    login_error = 'Invalid username or password' if error else None

    return templates.TemplateResponse(
        'login.html',
        {
            'request': request,
            'login_error': login_error,
            'reset_password': False,
        },
    )


@router.post('/login', response_class=RedirectResponse)
async def log_in_user(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    """Handle both regular and Alexa-initiated logins."""
    try:
        user = services.user.get_authenticated_user(form_data.username, form_data.password)
        if not user:
            login_url_base = request.url_for('log_in')
            login_url_with_error = f"{login_url_base}?error=true"
            return RedirectResponse(url=login_url_with_error, status_code=status.HTTP_302_FOUND)
    except Exception:
        login_url_base = request.url_for('log_in')
        login_url_with_error = f"{login_url_base}?error=true"
        return RedirectResponse(url=login_url_with_error, status_code=status.HTTP_302_FOUND)

    session_token = services.token.create_session(user.username)

    if request.session.get("oauth_state"):
        logger.debug("OAuth session detected, rebuilding redirect to /authorize.")
        
        path = request.url_for("authorize")
        
        params = {
            "client_id": request.session.get("oauth_client_id"),
            "redirect_uri": request.session.get("oauth_redirect_uri"),
            "state": request.session.get("oauth_state"),
            "response_type": "code",  # <-- THE FIX: Hardcode the required value
        }
        
        # Cleanly remove any keys that might be None
        valid_params = {k: v for k, v in params.items() if v is not None}
        
        query_string = urlencode(valid_params)
        next_url = f"{path}?{query_string}"
    else:
        next_url = request.cookies.get('redirect', request.url_for('home'))

    resp = RedirectResponse(next_url, status_code=status.HTTP_302_FOUND)
    resp.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        max_age=900,
        secure=True,
        samesite="Lax",
        path="/",
    )
    resp.delete_cookie(key='redirect')
    return resp

@router.get('/login/forgot-password', response_class=HTMLResponse)
async def forgot_password(request: Request, token_expired: bool = False):
    """Renders the forgot password page"""
    if await get_user_session(request):
        return RedirectResponse(router.url_path_for('home'), status_code=302)
    context: dict[str, Any] = {'request': request}
    if token_expired:
        context['password_reset_error'] = 'Unable to reset password. Token has expired. Please try again'
    return templates.TemplateResponse('password_reset.html', context)


@router.post('/login/forgot-password', response_class=HTMLResponse)
async def initiate_password_reset_email(
    request: Request,
    background_tasks: BackgroundTasks,
    username=Form(),
):
    """Sends a password reset email to the user"""
    _user_in_db = services.user.get_user(username, active_only=False)
    if _user_in_db:
        user = _user_in_db.cast(User)
        expires = timedelta(minutes=config.settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
        reset_token = services.token.create_token(user.username, expires)
        user.last_password_reset_token = reset_token.access_token
        services.user.update_user(user)
        password_reset_url = (
            str(request.base_url)[:-1]
            + router.url_path_for('reset_password')
            + f'?reset_token={user.last_password_reset_token}'
        )
        background_tasks.add_task(
            send_password_reset_email,
            password_reset_url=password_reset_url,
            username=user.username,
            email=user.email,
        )
    return templates.TemplateResponse(
        'password_reset.html',
        {'request': request, 'password_reset': True},
    )


@router.get('/login/reset-password', response_class=HTMLResponse)
async def reset_password(request: Request, reset_token: str | None = None):
    """Renders the password reset form, if the user is authenticated"""
    try:
        if not reset_token:
            raise InvalidTokenError()
        username = services.token.get_username_from_token(reset_token)
        _user_in_db = services.user.get_user(username, active_only=False)
        if not _user_in_db or _user_in_db.last_password_reset_token != reset_token:
            raise InvalidTokenError()
    except InvalidTokenError:
        return RedirectResponse(
            router.url_path_for('forgot_password') + '?token_expired=true',
            status_code=302,
        )
    return templates.TemplateResponse('change_password.html', {'request': request})


@router.post('/login/reset-password', response_class=HTMLResponse)
async def update_password(request: Request, reset_token: str | None = None, password: str = Form()):
    """Updates the user's password"""
    if len(password) < 8:
        return templates.TemplateResponse('change_password.html', {'request': request})
    try:
        if not reset_token:
            raise InvalidTokenError()
        username = services.token.get_username_from_token(reset_token)
        _user_in_db = services.user.get_user(username, active_only=False)
        if not _user_in_db or _user_in_db.last_password_reset_token != reset_token:
            raise InvalidTokenError()
        user = _user_in_db.cast(User)
    except InvalidTokenError:
        return RedirectResponse(
            router.url_path_for('forgot_password') + '?token_expired=true',
            status_code=302,
        )
    services.user.change_user_password(user, password)
    return RedirectResponse(router.url_path_for('log_in') + '?reset_password=true', status_code=302)


@router.get('/register', response_class=HTMLResponse)
async def register(request: Request, token_expired: bool = False):
    """Render the registration page"""
    response = RedirectResponse(router.url_path_for('home'), status_code=302)
    if await get_user_session(request):
        return response
    context: dict[str, Any] = {'request': request}
    if token_expired:
        context['registration_error'] = 'Unable to complete registration. Token has expired'
    return templates.TemplateResponse('register.html', context)


@router.post('/register', response_class=HTMLResponse)
async def initiate_registration_email(
    request: Request,
    background_tasks: BackgroundTasks,
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    if len(form_data.password) < 8:
        return templates.TemplateResponse(
            'register.html',
            {
                'request': request,
                'registration_error': 'Password must be at least 8 characters long',
                'username': form_data.username,
            },
        )
    try:
        clean_email = form_data.username.strip().lower()
        if config.settings.USE_WHITELIST and clean_email not in config.secrets.EMAIL_WHITELIST:
            raise WhitelistError()
        new_user = services.user.create_new_user(
            username=clean_email,
            email=clean_email,
            password=form_data.password,
            token_service=services.token,
            disabled=True,
        )
    except (ClientError, UserAlreadyExistsError):
        return templates.TemplateResponse(
            'register.html',
            {
                'request': request,
                'registration_error': 'Username already taken!',
                'username': form_data.username,
            },
        )
    except WhitelistError:
        return templates.TemplateResponse(
            'register.html',
            {
                'request': request,
                'registration_error': 'You are not whitelisted on this app',
                'username': form_data.username,
            },
        )
    except Exception as e:
        logging.error('Unhandled exception when trying to register a new user (%s)', form_data.username)
        logging.error('%s: %s', type(e).__name__, e)
        return templates.TemplateResponse(
            'register.html',
            {
                'request': request,
                'registration_error': 'An unknown error occurred during registration',
                'username': form_data.username,
            },
        )
    registration_url = (
        str(request.base_url)[:-1]
        + router.url_path_for('complete_registration')
        + f'?registration_token={new_user.last_registration_token}'
    )
    background_tasks.add_task(
        send_registration_email,
        registration_url=registration_url,
        username=form_data.username,
        email=form_data.username,
    )
    return templates.TemplateResponse('register.html', {'request': request, 'registration_email_sent': True})


@router.get('/complete_registration', response_class=HTMLResponse)
async def complete_registration(registration_token: str | None = None):
    """Enable the user and start a logged-in session."""
    try:
        if not registration_token:
            raise InvalidTokenError()
        username = services.token.get_username_from_token(registration_token)
        _user_in_db = services.user.get_user(username, active_only=False)
        if not _user_in_db or _user_in_db.last_registration_token != registration_token:
            raise InvalidTokenError()
    except InvalidTokenError:
        return RedirectResponse(router.url_path_for('register') + '?token_expired=true', status_code=302)
    user = _user_in_db.cast(User)
    user.disabled = False
    user.last_registration_token = None
    services.user.update_user(user, remove_expiration=True)
    session_token = services.token.create_session(user.username)
    resp = RedirectResponse(router.url_path_for('home'), status_code=302)
    resp.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        max_age=900,
        secure=True,
        samesite="Lax",
    )
    return resp


@router.post('/logout', response_class=RedirectResponse)
async def log_out_user():
    """Clears the session cookie and redirects to the home page."""
    response = RedirectResponse(url=router.url_path_for('home'), status_code=status.HTTP_302_FOUND)
    
    # Delete the cookie from the root path
    response.delete_cookie("session_token", path="/") # <-- NOTE THE PATH
    
    return response


@router.post('/delete-account', response_class=HTMLResponse)
async def delete_user(request: Request, response: Response):
    """Completely remove all user data"""
    response = RedirectResponse(router.url_path_for('home'), status_code=302)
    user = await get_user_session(request)
    if not user:
        return response
    services.user.delete_user(user.username)
    await clear_user_session(response)
    return response