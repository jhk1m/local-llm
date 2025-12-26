# app.py - INCREMENTAL BUILD STEP: CORE ROUTES ACTIVE, DEBUGGING LOGS ACTIVE

from __future__ import annotations

import logging
import os
import pathlib

import config
from fastapi import FastAPI, Request, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from services.serve import CreateServices
from starlette.middleware.sessions import SessionMiddleware

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

current_dir = pathlib.Path(__file__).parent

app_secrets = config.secrets
app_settings = config.settings

app = FastAPI(
    title=app_settings.APP_TITLE,
    version=app_settings.APP_VERSION,
    debug=True,
)

app.add_middleware(
    SessionMiddleware,
    secret_key=app_secrets.DB_SECRET_KEY,
    https_only=True,
    same_site="lax"
)

app.mount(
    '/static',
    StaticFiles(directory=os.path.join(current_dir, 'static')),
    name='static',
)

templates = Jinja2Templates(directory=current_dir / 'static' / 'templates')
services = CreateServices()

# --- BEGIN ROUTER IMPORTS AND INCLUSIONS (INCREMENTAL) ---
# === Route Setup ===
from routes import account_linking, alexa, auth, core

# from routes import account_linking, alexa

# Include routers
app.include_router(core.router, include_in_schema=False)   # type: ignore
app.include_router(alexa.auth_router, include_in_schema=False)  # type: ignore
app.include_router(account_linking.api_router)   # type: ignore
app.include_router(auth.router, include_in_schema=False)   # type: ignore
app.include_router(alexa.frontend_router)

for route in app.routes:
    logger.debug(f'...............ROUTE NAME: {route.name} PATH: {route.path}')


def secure_static_url(request: Request, path: str):
    # Use the 'request' object to determine the protocol
    protocol = 'https' if request.url.scheme == 'https' else 'http'
    return f'{protocol}://{request.base_url.netloc}/static/{path}'

# Add a custom template context function to generate secure URLs


@app.on_event('startup')
async def startup_event():
    templates.env.globals['secure_static_url'] = secure_static_url

# default route

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get('/', response_class=RedirectResponse, include_in_schema=False)
def home():
    return RedirectResponse(core.router.url_path_for('home'), status_code=status.HTTP_301_MOVED_PERMANENTLY)

# --- END ROUTER IMPORTS AND INCLUSIONS (INCREMENTAL) ---