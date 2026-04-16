# BSD 2-Clause License
#
# Apprise - Push Notification Library.
# Copyright (c) 2026, Chris Caron <lead2gold@gmail.com>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# To generate a private key file for your service account:
#
#  1. In the Firebase console, open Settings > Service Accounts.
#  2. Click Generate New Private Key, then confirm by clicking Generate Key.
#  3. Securely store the JSON file containing the key.

import base64
import calendar
from datetime import datetime, timedelta, timezone
import json
from json.decoder import JSONDecodeError
from urllib.parse import urlencode as _urlencode

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import asymmetric, hashes, serialization
import requests

from ...logger import logger


class GoogleOAuth:
    """A OAuth simplified implimentation to Google's Firebase Cloud
    Messaging."""

    scopes = [
        "https://www.googleapis.com/auth/firebase.messaging",
    ]

    # 1 hour in seconds (the lifetime of our token)
    access_token_lifetime_sec = timedelta(seconds=3600)

    # The default URI to use if one is not found
    default_token_uri = "https://oauth2.googleapis.com/token"

    # Taken right from google.auth.helpers:
    clock_skew = timedelta(seconds=10)

    def __init__(
        self, user_agent=None, timeout=(5, 4), verify_certificate=True
    ):
        """Initialize our OAuth object."""

        # Wether or not to verify ssl
        self.verify_certificate = verify_certificate

        # Our (connect, read) timeout
        self.request_timeout = timeout

        # assign our user-agent if defined
        self.user_agent = user_agent

        # initialize our other object variables
        self.__reset()

    def __reset(self):
        """Reset object internal variables."""

        # Google Keyfile Encoding
        self.encoding = "utf-8"

        # Our retrieved JSON content (unmangled)
        self.content = None

        # Our generated key information we cache once loaded
        self.private_key = None

        # Our keys we build using the provided content
        self.__refresh_token = None
        self.__access_token = None
        self.__access_token_expiry = datetime.now(timezone.utc)

    def load(self, path):
        """Generate our SSL details."""

        # Reset our objects
        self.content = None
        self.private_key = None
        self.__access_token = None
        self.__access_token_expiry = datetime.now(timezone.utc)

        try:
            with open(path, encoding=self.encoding) as fp:
                self.content = json.loads(fp.read())

        except OSError:
            logger.debug(f"FCM keyfile {path} could not be accessed")
            return False

        except JSONDecodeError as e:
            logger.debug(
                f"FCM keyfile {path} generated a JSONDecodeError: {e}"
            )
            return False

        if not isinstance(self.content, dict):
            logger.debug(f"FCM keyfile {path} is incorrectly structured")
            self.__reset()
            return False

        # Verify we've got the correct tokens in our content to work with
        is_valid = next(
            (
                False
                for k in (
                    "client_email",
                    "private_key_id",
                    "private_key",
                    "type",
                    "project_id",
                )
                if not self.content.get(k)
            ),
            True,
        )

        if not is_valid:
            logger.debug(f"FCM keyfile {path} is missing required information")
            self.__reset()
            return False

        # Verify our service_account type
        if self.content.get("type") != "service_account":
            logger.debug(f"FCM keyfile {path} is not of type service_account")
            self.__reset()
            return False

        # Prepare our private key which is in PKCS8 PEM format
        try:
            self.private_key = serialization.load_pem_private_key(
                self.content.get("private_key").encode(self.encoding),
                password=None,
                backend=backends.default_backend(),
            )

        except (TypeError, ValueError):
            # ValueError: If the PEM data could not be decrypted or if its
            #             structure could not be decoded successfully.
            # TypeError:  If a password was given and the private key was
            #             not encrypted. Or if the key was encrypted but
            #             no password was supplied.
            logger.error("FCM provided private key is invalid.")
            self.__reset()
            return False

        except UnsupportedAlgorithm:
            # If the serialized key is of a type that is not supported by
            # the backend.
            logger.error("FCM provided private key is not supported")
            self.__reset()
            return False

        # We've done enough validation to move on
        return True

    @property
    def access_token(self):
        """Returns our access token (if it hasn't expired yet)

        - if we do not have one we'll fetch one.
        - if it expired, we'll renew it
        - if a key simply can't be acquired, then we return None
        """
        pass

    @property
    def project_id(self):
        """Returns the project id found in the file."""
        pass
