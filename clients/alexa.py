from __future__ import annotations

import time
from json import JSONDecodeError
from typing import Any
from typing import cast
from uuid import uuid4

import requests
from app_config import AppSecrets
from app_config import AppSettings
from clients import aws
from pydantic import ValidationError
from requests import HTTPError
from requests import Response

LWA_URL = 'https://api.amazon.com/auth/o2/token'
ALEXA_MESSAGE_API_URL = 'https://api.amazonalexa.com/v1/skillmessages/users/{user_id}'

# TODO: make these inherit from a custom exception type
NO_RESPONSE_EXCEPTION = 'Could not find a response from Alexa'
NO_RESPONSE_DATA_EXCEPTION = 'Alexa returned a response, but there was no response data'

app_secrets = AppSecrets()
app_settings = AppSettings()

class ListManagerClient:
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

    ### Base ###

    def _refresh_token(self) -> None:
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
            print(r.content)
            raise Exception(
                'Unable to obtain Alexa Skill Messaging API Token; invalid JSON response',
            )

        if 'access_token' not in response_json:
            print(response_json)
            raise Exception(
                'Alexa Skill Messaging API Token missing from response',
            )

        self.access_token = response_json['access_token']
        self.expiration = time.time() + response_json['expires_in']

    def _poll_for_event_response(self, event_id: str, poll_frequency=0.5, timeout=20) -> dict[str, Any]:
        """Poll DynamoDB for a particular event response and returns the full JSON"""

        start_time = time.time()
        while True:
            event = self.event_callback_db.get(event_id)
            if event:
                return event

            if time.time() >= start_time + timeout:
                raise Exception('Timed out waiting for callback')

            # the event doesn't exist yet, so we keep polling
            time.sleep(poll_frequency)
            continue