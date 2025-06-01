from __future__ import annotations

import logging
import boto3
from base64 import b64decode, b64encode
from datetime import timedelta
from typing import Any

from clients import aws
from models.aws import DynamoDBAtomicOp
from models.core import RateLimitCategory, User, UserInDB, WhitelistError
from passlib.context import CryptContext

from .auth_token import AuthTokenService

import config

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


class UserAlreadyExistsError(Exception):
    def __init__(self):
        super().__init__('User already exists')


class UserIsNotRegisteredError(Exception):
    def __init__(self):
        super().__init__('User has not completed registration')


class UserIsDisabledError(Exception):
    def __init__(self):
        super().__init__('User is disabled')


class InvalidPassword(Exception):
    def __init__(self):
        super().__init__('Invalid password')


class UserService:
    def __init__(self) -> None:
        self._db: aws.DynamoDB | None = None
        self.kms_client = boto3.client('kms', region_name=config.secrets.AWS_REGION)


    @property
    def db(self):
        if not self._db:
            self._db = aws.DynamoDB(config.settings.USERS_TABLENAME, config.settings.USERS_PK)
        return self._db

    def get_user(self, username: str, active_only=True) -> UserInDB | None:
        logger.debug('...............GET_USER CALLED FOR USER: %s', username)
        user_data = self.db.get(username.strip().lower())
        if not user_data:
            return None
        user = UserInDB.parse_obj(user_data)
        if active_only and user.disabled:
            return None
        return user

    def get_user_by_alexa_id(self, alexa_user_id: str) -> UserInDB | None:
        results = self.db.query("alexa_linking.alexa_user_id", alexa_user_id)
        if results:
            return UserInDB.parse_obj(results[0])
        return None

    def link_alexa_account(self, alexa_user_id: str) -> None:
        if not self.alexa_linking:
            self.alexa_linking = {}
        self.alexa_linking["alexa_user_id"] = alexa_user_id

    def delete_user(self, username: str) -> None:
        self.db.delete(username)

    def get_usernames_by_secondary_index(self, gsi_key: str, gsi_value: str) -> list[str]:
        user_data = self.db.query(gsi_key, gsi_value)
        return [str(data.get(config.settings.USERS_PK)) for data in user_data]
    
    def get_user_by_auth_code(self, auth_code: str) -> UserInDB | None:
        """Retrieves a user by their Alexa authorization code."""
        # This assumes alexa_linking.auth_code is indexed in DynamoDB
        # You might need a GSI (Global Secondary Index) on 'alexa_linking.auth_code'
        # if you are querying directly on a nested attribute.
        # If not, you might need to scan (less efficient for large tables) or query by another index
        # and then filter in application code.
        
        # Example if alexa_linking.auth_code is a top-level attribute or part of a GSI:
        results = self.db.query("alexa_linking.auth_code", auth_code) # Adjust if your DynamoDB query needs a different path/index
        if results:
            return UserInDB.parse_obj(results[0])
        return None

    def authenticate_user(self, user: UserInDB, password: str) -> User | None:
        logger.debug('...............AUTHENTICATE_USER: %s', user)
        if not pwd_context.verify(password, user.hashed_password):
            self.increment_failed_login_counter(user)
            return None
        if user.incorrect_login_attempts and user.incorrect_login_attempts > 0:
            user.incorrect_login_attempts = 0
            self.update_user(user)
        return user.cast(User)

    def get_authenticated_user(self, username: str, password: str) -> User | None:
        logger.debug('...............GET_AUTHENTICATED_USER CALLED FOR USER: %s', username)
        user = self.get_user(username, active_only=False)
        if not user:
            return None
        if user.disabled:
            if user.user_expires:
                raise UserIsNotRegisteredError()
            else:
                raise UserIsDisabledError()
        if config.settings.USE_WHITELIST and user.email not in config.secrets.EMAIL_WHITELIST:
            raise WhitelistError()
        return self.authenticate_user(user, password)

    def create_new_user(self, username: str, email: str, password: str,
                        token_service: AuthTokenService,
                        api_token: str | None = None,
                        access_token: str | None = None,
                        disabled: bool = False,
                        create_registration_token: bool = True,) -> User:
        allow_update = False
        existing_user = self.get_user(username, active_only=False)
        if existing_user:
            if not existing_user.disabled:
                raise UserAlreadyExistsError()
            allow_update = True
        try:
            logger.debug('...............CREATE_NEW_USER CALLED: %s', username)
            new_user = UserInDB(
                username=username.strip().lower(),
                email=email.strip().lower(),
                hashed_password=pwd_context.hash(password),
                disabled=disabled,
                api_token=api_token,
                access_token=access_token,
            )
        except Exception as e:
            logging.error(f'Unexpected error in create_new_user: {str(e)}')

        if disabled:
            new_user.set_expiration(config.settings.ACCESS_TOKEN_EXPIRE_MINUTES_REGISTRATION * 60)

        if create_registration_token:
            access_token_expires = timedelta(
                minutes=config.settings.ACCESS_TOKEN_EXPIRE_MINUTES_REGISTRATION
            )
            # Use injected token_service
            registration_token = token_service.create_token(new_user.username, access_token_expires)
            new_user.last_registration_token = registration_token.access_token

        self.db.put(new_user.dict(exclude_none=True), allow_update=allow_update)
        return new_user.cast(User)

    def update_user(self, user: User, remove_expiration: bool = False) -> None:
        user_to_update = self.get_user(user.username, active_only=False)
        if not user_to_update:
            raise ValueError(f'User {user.username} does not exist')
        logger.debug('...............UPDATING_USER: %s', user_to_update.username)
        for key, value in user.dict().items():
            if value is not None:
                setattr(user_to_update, key, value)
        if user_to_update.username:
            user_to_update.username = user_to_update.username.strip().lower()
        if user_to_update.email:
            user_to_update.email = user_to_update.email.strip().lower()
        if user_to_update.api_token:
            user_to_update.api_token = user_to_update.api_token.strip().lower()
        if user_to_update.access_token:
            user_to_update.access_token = user_to_update.access_token.strip().lower()
        data = user_to_update.dict(exclude_none=True)
        if remove_expiration:
            data['user_expires'] = None
        self.db.put(data)

    def update_atomic_user_field(self, user: User, field: str, value: int = 1,
                                  operation: DynamoDBAtomicOp = DynamoDBAtomicOp.increment) -> int:
        return self.db.atomic_op(user.username.strip().lower(), field, value, op=operation)

    def change_user_password(self, user: User, new_password: str,
                              enable_user: bool = True,
                              clear_password_reset_token: bool = True) -> None:
        user_to_update = self.get_user(user.username, active_only=False)
        if not user_to_update:
            raise ValueError(f'User {user.username} does not exist')
        user_to_update.hashed_password = pwd_context.hash(new_password)
        if enable_user:
            user_to_update.disabled = False
        data = user_to_update.dict(exclude_none=True)
        if clear_password_reset_token:
            data['last_password_reset_token'] = None
        self.db.put(data)

    def increment_failed_login_counter(self, user: User) -> User:
        if user.incorrect_login_attempts is None:
            user.incorrect_login_attempts = 1
            self.update_user(user)
            return user
        user.incorrect_login_attempts += 1
        if user.incorrect_login_attempts < config.settings.LOGIN_LOCKOUT_ATTEMPT:
            user.incorrect_login_attempts = self.update_atomic_user_field(user, 'incorrect_login_attempts')
            return user
        user.disabled = True
        user.incorrect_login_attempts = 0
        self.update_user(user)
        return user

    def update_rate_limit(self, user: User, category: RateLimitCategory,
                          operation: DynamoDBAtomicOp, value: int = 1,
                          new_expires: int | None = None) -> None:
        field_root = f'rate_limit_map.{category.value}'
        self.update_atomic_user_field(user, f'{field_root}.value', value=value, operation=operation)
        if new_expires:
            self.update_atomic_user_field(user, f'{field_root}.expires', value=new_expires,
                                           operation=DynamoDBAtomicOp.overwrite)
