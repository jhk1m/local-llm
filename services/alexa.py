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
        
        # Store client_id and redirect_uri with the auth code
        user.alexa_linking.auth_code = code
        user.alexa_linking.auth_code_expires = int(time.time()) + expires_in
        user.alexa_linking.client_id = client_id # New: Store client_id
        user.alexa_linking.redirect_uri = redirect_uri # New: Store redirect_uri
        
        self.user_service.update_user(user) # Persist changes to user model
        logger.debug(f"Generated auth code '{code}' for user {user.username}. Expires in {expires_in}s. Client ID: {client_id}, Redirect URI: {redirect_uri}")
        return code

    def validate_auth_code(self, auth_code: str, client_id: str, redirect_uri: str) -> User | None:
        """
        Validates an authorization code, client_id, and redirect_uri,
        and returns the associated user if valid.
        This function should also invalidate the code after use.
        """
        # Find user by auth code (you'll need to query your DB or cache for the user associated with this code)
        # This assumes your DynamoDB `User` model can be queried by `alexa_linking.auth_code`
        user = self.user_service.get_user_by_auth_code(auth_code) # You'll need to implement this in UserService

        if not user:
            logger.error(f"Auth code '{auth_code}' not found or no user associated.")
            return None

        # Check if the code is valid (not expired, matches what's stored)
        if not user.is_alexa_auth_code_valid(auth_code):
            logger.error(f"Auth code '{auth_code}' for user {user.username} is invalid or expired.")
            user.clear_alexa_auth_code() # Clear invalid/expired code
            self.user_service.update_user(user)
            return None

        # Validate client_id and redirect_uri against what was stored with the code
        if user.alexa_linking.client_id != client_id:
            logger.error(f"Auth code '{auth_code}' for user {user.username}: client_id mismatch. Expected '{user.alexa_linking.client_id}', got '{client_id}'.")
            user.clear_alexa_auth_code() # Invalidate code on mismatch
            self.user_service.update_user(user)
            return None
        
        if user.alexa_linking.redirect_uri != redirect_uri:
            logger.error(f"Auth code '{auth_code}' for user {user.username}: redirect_uri mismatch. Expected '{user.alexa_linking.redirect_uri}', got '{redirect_uri}'.")
            user.clear_alexa_auth_code() # Invalidate code on mismatch
            self.user_service.update_user(user)
            return None

        # Important: Invalidate the auth code after successful validation (single-use)
        user.clear_alexa_auth_code()
        self.user_service.update_user(user)
        logger.debug(f"Auth code '{auth_code}' successfully validated and invalidated for user {user.username}.")
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