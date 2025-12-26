# clients/alexa.py - CORRECTED

from __future__ import annotations

import time
from json import JSONDecodeError
from typing import Any
import requests
import logging
from app_config import AppSecrets, AppSettings
from clients import aws
from requests import HTTPError

LWA_URL = 'https://api.amazon.com/auth/o2/token'
ALEXA_MESSAGE_API_URL = 'https://api.amazonalexa.com/v1/skillmessages/users/{user_id}'

app_secrets = AppSecrets()
app_settings = AppSettings()
logger = logging.getLogger(__name__)

# --- FIX #1: The class has been renamed to match what your service is importing. ---
class AlexaAPIClient:
    """Manages low-level Alexa Skills API interaction"""

    def __init__(self, max_attempts: int = 3, rate_limit_throttle: int = 5) -> None:
        self.access_token: str | None = None
        self.expiration: float = -1
        self._event_callback_db: aws.DynamoDB = None
        self.max_attempts = max_attempts
        self.rate_limit_throttle = rate_limit_throttle

    @property
    def event_callback_db(self):
        if not self._event_callback_db:
            self._event_callback_db = aws.DynamoDB(
                app_settings.ALEXA_EVENT_CALLBACK_TABLENAME, app_settings.ALEXA_EVENT_CALLBACK_PK,
            )
        return self._event_callback_db

    def _refresh_token(self) -> None:
        """Refreshes the Skill Messaging API token."""
        payload = {
            'grant_type': 'client_credentials',
            'client_id': app_secrets.ALEXA_CLIENT_ID,
            'client_secret': app_secrets.ALEXA_CLIENT_SECRET,
            'scope': 'alexa:skill_messaging',
        }
        r = requests.post(LWA_URL, json=payload)
        r.raise_for_status()

        try:
            response_json = r.json()
        except JSONDecodeError:
            logger.error("Failed to decode LWA response: %s", r.content)
            raise Exception('Unable to obtain Alexa Skill Messaging API Token; invalid JSON response')

        if 'access_token' not in response_json:
            logger.error("access_token missing from LWA response: %s", response_json)
            raise Exception('Alexa Skill Messaging API Token missing from response')

        self.access_token = response_json['access_token']
        self.expiration = time.time() + response_json['expires_in']

    # --- FIX #2: Added the method that your AlexaService requires. ---
    def send_skill_message(self, user_id: str, payload: dict) -> None:
        """Sends a proactive message to a user via the Alexa Skill Messaging API."""
        if not self.access_token or time.time() >= self.expiration:
            logger.info("Refreshing Alexa API token.")
            self._refresh_token()

        headers = {
            'Authorization': f'Bearer {self.access_token}'
        }
        url = ALEXA_MESSAGE_API_URL.format(user_id=user_id)
        
        try:
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
            logger.info(f"Successfully sent skill message to user {user_id}")
        except HTTPError as e:
            logger.error(f"HTTP error sending skill message: {e.response.status_code} - {e.response.text}")
            # Depending on your needs, you might want to raise a custom exception here.
            raise
    
    def _poll_for_event_response(self, event_id: str, poll_frequency=0.5, timeout=20) -> dict[str, Any]:
        """Polls DynamoDB for a particular event response and returns the full JSON"""
        start_time = time.time()
        while True:
            event = self.event_callback_db.get(event_id)
            if event:
                return event
            if time.time() >= start_time + timeout:
                raise Exception('Timed out waiting for callback')
            
            time.sleep(poll_frequency)