
from __future__ import annotations

import json
from typing import List
from pathlib import Path
from pydantic import BaseSettings


class AppSecrets(BaseSettings):
    ### AWS ###
    AWS_REGION: str =

    ### Database ###
    DB_SECRET_KEY: str =
    DB_ALGORITHM: str =

    ### KMS ###
    KMS_ARN: str 

    ### SMTP ###
    SMTP_SERVER: str =
    SMTP_PORT: int =
    SMTP_SENDER: str =
    SMTP_USERNAME: str =
    SMTP_PASSWORD: str =

    ### Access ###
    ALEXA_CLIENT_ID: str =
    ALEXA_CLIENT_SECRET: str = 
    EMAIL_WHITELIST: List[str] = 

    ### Alexa ###
    ALEXA_CLIENT_ID: str = 
    ALEXA_CLIENT_SECRET: str = 
    ALEXA_SKILL_ID: str = 
    ALEXA_REDIRECT_URI: list[str] = 

    JWT_SECRET_KEY: str = 
    ### Ollama ###
    OLLAMA_URL: str = 
    OLLAMA_MODEL: str = 

    ### SSL ###
    SSL_KEY_PATH: str =
    SSL_CERT_PATH: str = 

    ### EC2 ###
    SSH_KEY: str = 
    EC2_USER: str = 
    EC2_HOST: str =

    ### Encryption ###
    ENCRYPTION_KEY_V1: str =
    ENCRYPTION_KEY_V2: str = 



class AppSettings(BaseSettings):
    ### About ###
    APP_TITLE: str = 
    APP_VERSION: str =
    INTERNAL_APP_NAME: str =

    ### App ###
    DEBUG: bool = True
    USE_WHITELIST: bool = False

    ### Token Expiry ###
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 30
    ACCESS_TOKEN_EXPIRE_MINUTES_TEMPORARY: int = 10
    REFRESH_TOKEN_EXPIRE_DAYS: int = 60 * 24 * 365 * 10
    ACCESS_TOKEN_EXPIRE_MINUTES_INTEGRATION: int = 60 * 24 * 365 * 100
    ACCESS_TOKEN_EXPIRE_MINUTES_REGISTRATION: int = 15
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 15

    ### Login ###
    LOGIN_LOCKOUT_ATTEMPT: int = 5

    ### Database Definition ###
    ALEXA_EVENT_CALLBACK_TABLENAME: str =
    ALEXA_EVENT_CALLBACK_PK: str = 
    USERS_TABLENAME: str =
    USERS_PK: str =

    ### API Rate Limits ###
    RATE_LIMIT_BY_MINUTE_READ: int = 60
    RATE_LIMIT_BY_MINUTE_MODIFY: int = 30
    RATE_LIMIT_BY_MINUTE_SYNC: int = 60

    ### Alexa Internal ###
    ALEXA_SECRET_HEADER_KEY: str =
    ALEXA_INTERNAL_SOURCE_ID: str = 
    ALEXA_API_SOURCE_ID: str =
