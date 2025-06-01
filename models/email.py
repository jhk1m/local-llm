
from __future__ import annotations

import logging
import pathlib
from email.message import EmailMessage

from app_config import AppSecrets
from app_config import AppSettings
from fastapi.templating import Jinja2Templates

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app_secrets = AppSecrets()
app_settings = AppSettings()

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
email_templates = Jinja2Templates(
    directory=BASE_DIR / 'static' / 'email_template'
)


class GenericEmailTemplate:
    def __init__(self, template: str, is_html: bool = False) -> None:
        self.template = template
        self.is_html = is_html

    def message(
        self,
        subject: str,
        sender: str,
        recipients: str | list[str],
        cc: str | list[str] | None = None,
        bcc: str | list[str] | None = None,
        **kwargs,
    ) -> EmailMessage:
        """Constructs a message to be sent via SMTP. Provide merge fields as kwargs"""

        body_template = email_templates.get_template(self.template)
        logger.debug('...............BODY_TEMPLATE: %s', body_template)
        body = body_template.render(**kwargs)

        if isinstance(recipients, list):
            recipients = ', '.join(recipients)

        if isinstance(cc, list):
            cc = ', '.join(cc)

        if isinstance(bcc, list):
            bcc = ', '.join(bcc)

        msg = EmailMessage()
        if self.is_html:
            msg.set_content("This email requires an HTML-compatible client.")
            msg.add_alternative(body, subtype='html')
        else:
            msg.set_content(body)

        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = recipients
        if cc:
            msg['Cc'] = cc
        if bcc:
            msg['Bcc'] = bcc

        logger.debug('...............MSG_CONTENT: %s', msg)
        return msg


class RegistrationEmail:
    def __init__(self) -> None:
        self.template = GenericEmailTemplate('registration.html', is_html=True)

    def message(
        self,
        recipient_username: str,
        recipient_email: str,
        registration_url: str,
    ) -> EmailMessage:
        # Debug log
        logger.debug(
            '...............Creating registration email for %s at %s',
            recipient_username,
            recipient_email,
        )
        subject = f'Confirm your email for {app_settings.APP_TITLE}'
        return self.template.message(
            subject,
            sender=app_secrets.SMTP_SENDER,
            recipients=recipient_email,
            name=recipient_username,
            registration_url=registration_url,
        )


class PasswordResetEmail:
    def __init__(self) -> None:
        self.template = GenericEmailTemplate(
            'password_reset.html', is_html=True,
        )

    def message(
        self,
        recipient_username: str,
        recipient_email: str,
        password_reset_url: str,
    ) -> EmailMessage:
        subject = f'Reset your password for {app_settings.APP_TITLE}'
        return self.template.message(
            subject,
            sender=app_secrets.SMTP_SENDER,
            recipients=recipient_email,
            name=recipient_username,
            password_reset_url=password_reset_url,
        )
