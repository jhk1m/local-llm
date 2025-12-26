# services/alexa.py - MODIFIED

from __future__ import annotations

import logging
import secrets
import string
import time # Import time for int(time.time())

from models.core import User
from clients.alexa import AlexaAPIClient
from services.user import UserService # Ensure this import is correct


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class AlexaService:
    def __init__(self) -> None:
        self.client = AlexaAPIClient()
        self.user_service = UserService()

    def create_auth_code(self, user: User, client_id: str, redirect_uri: str, expires_in: int = 300) -> str:
        """
        Generates and sets a unique, short-lived authorization code for a user,
        including client_id and redirect_uri for later validation.
        """
        code = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
        user.set_alexa_auth_code(code, expires_in)
        
        # Store client_id and redirect_uri with the auth code
        user.alexa_linking.client_id = client_id # New: Store client_id
        user.alexa_linking.redirect_uri = redirect_uri # New: Store redirect_uri
        user.alexa_auth_code = code 

        logger.debug(f"ATTEMPTING TO SAVE USER OBJECT: {user.dict()}")
        self.user_service.update_user(user) # Persist changes to user model
        logger.debug(f"Generated auth code '{code}' for user {user.username}. Expires in {expires_in}s. Client ID: {client_id}, Redirect URI: {redirect_uri}")
        return code

    def validate_auth_code(self, auth_code: str, client_id: str, redirect_uri: str) -> User | None:
        """
        Validates an authorization code, client_id, and redirect_uri,
        and returns the associated user if valid.
        This function should also invalidate the code after use.
        """
        user_in_db = self.user_service.get_user_by_auth_code(auth_code)  # NEW path
        if not user_in_db:
            logger.error("Auth code not found")
            return None
        user = user_in_db.cast(User)
        # check expiry and client/redirect, then invalidate:
        if not user.is_alexa_auth_code_valid(auth_code):
            user.clear_alexa_auth_code()
            self.user_service.update_user(user)
            return None
        if user.alexa_linking.client_id != client_id or user.alexa_linking.redirect_uri != redirect_uri:
            user.clear_alexa_auth_code()
            self.user_service.update_user(user)
            return None
        user.alexa_auth_code = None
        user.clear_alexa_auth_code()
        self.user_service.update_user(user)
        return user

    # ... rest of your AlexaService methods ...
    def send_message(self, user_id: str, payload: dict) -> None:
        self.client.send_skill_message(user_id, payload)

    def link_user(self, user: User, alexa_user_id: str):
        user.link_alexa_account(alexa_user_id)
        self.user_service.update_user(user) # Persist the link

    def unlink_user(self, user: User):
        user.unlink_alexa_account()
        self.user_service.update_user(user) # Persist the unlink

    # Removed set_auth_code as its logic is now in create_auth_code
    # Removed the old validate_auth_code which only checked user.is_alexa_auth_code_valid