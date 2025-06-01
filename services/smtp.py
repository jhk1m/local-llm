from __future__ import annotations

import logging
from email.message import EmailMessage
from smtplib import SMTP
from smtplib import SMTPException

import config

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class SMTPService:
    def __init__(
        self,
        server: str = None,
        port: int = None,
        username: str = None,
        password: str = None,
        use_tls: bool = True,
    ) -> None:

        self.server = server or config.secrets.SMTP_SERVER
        self.port = port or config.secrets.SMTP_PORT
        self.username = username or config.secrets.SMTP_USERNAME
        self.password = password or config.secrets.SMTP_PASSWORD
        self.use_tls = use_tls

    def send(self, msg: EmailMessage) -> None:
        smtp = None
        try:
            smtp = SMTP(self.server, port=self.port)
            smtp.ehlo()
            if self.use_tls:
                smtp.starttls()

            logger.debug("SMTP Login with user: %s", self.username)
            smtp.login(self.username, self.password)

            logger.debug("SMTP sending message to: %s", msg['To'])
            smtp.send_message(msg)
            logger.debug("...............EMAIL SENT SUCCESSFULLY")

        except SMTPException as e:
            logger.error("SMTPException occurred: %s", str(e))
            logger.debug("Email not sent (SMTPException):", exc_info=True)

        except Exception as e:
            logger.error("Unexpected error occurred: %s", str(e))
            logger.debug("Email not sent (Exception):", exc_info=True)

        finally:
            if smtp:
                smtp.quit()