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

# Great sources
# - https://github.com/matrix-org/matrix-python-sdk
# - https://github.com/matrix-org/synapse/blob/master/docs/reverse_proxy.rst
#
# End-to-End Encryption references:
# - https://spec.matrix.org/v1.11/client-server-api/
#   #end-to-end-encryption
# - https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md
# - https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md
#
import contextlib
from json import dumps, loads
import re
from time import time
import uuid

from markdown import markdown
import requests

from ...common import (
    NotifyFormat,
    NotifyImageSize,
    NotifyType,
    PersistentStoreMode,
)
from ...exception import AppriseException
from ...locale import gettext_lazy as _
from ...url import PrivacyMode
from ...utils.parse import (
    is_hostname,
    parse_bool,
    parse_list,
    validate_regex,
)
from ..base import NotifyBase
from .e2ee import (
    MATRIX_E2EE_SUPPORT,
    MatrixMegOlmSession,
    MatrixOlmAccount,
    encrypt_attachment,
    verify_device_keys,
    verify_signed_otk,
)

# Define default path
MATRIX_V1_WEBHOOK_PATH = "/api/v1/matrix/hook"
MATRIX_V2_API_PATH = "/_matrix/client/r0"
MATRIX_V3_API_PATH = "/_matrix/client/v3"
MATRIX_V3_MEDIA_PATH = "/_matrix/media/v3"
MATRIX_V2_MEDIA_PATH = "/_matrix/media/r0"


class MatrixDiscoveryException(AppriseException):
    """Apprise Matrix Exception Class."""


# Extend HTTP Error Messages
MATRIX_HTTP_ERROR_MAP = {
    403: "Unauthorized - Invalid Token.",
    429: "Rate limit imposed; wait 2s and try again",
}

# Matrix Room Syntax
IS_ROOM_ALIAS = re.compile(
    r"^\s*(#|%23)?(?P<room>[A-Za-z0-9._=-]+)((:|%3A)"
    r"(?P<home_server>[A-Za-z0-9.-]+))?\s*$",
    re.I,
)

# Room ID MUST start with an exclamation to avoid ambiguity
IS_ROOM_ID = re.compile(
    r"^\s*(!|&#33;|%21)(?P<room>[A-Za-z0-9._=-]+)((:|%3A)"
    r"(?P<home_server>[A-Za-z0-9.-]+))?\s*$",
    re.I,
)

# Matrix User ID (for DM targets); must start with @
IS_USER = re.compile(
    r"^\s*(@|%40)(?P<user>[A-Za-z0-9._=+/-]+)((:|%3A)"
    r"(?P<home_server>[A-Za-z0-9.-]+))?\s*$",
    re.I,
)


# Matrix is_image check
IS_IMAGE = re.compile(r"^image/.*", re.I)


class MatrixMessageType:
    """The Matrix Message types."""

    TEXT = "text"
    NOTICE = "notice"


# matrix message types are placed into this list for validation purposes
MATRIX_MESSAGE_TYPES = (
    MatrixMessageType.TEXT,
    MatrixMessageType.NOTICE,
)


class MatrixVersion:
    # Version 2
    V2 = "2"

    # Version 3
    V3 = "3"


# webhook modes are placed into this list for validation purposes
MATRIX_VERSIONS = (
    MatrixVersion.V2,
    MatrixVersion.V3,
)


class MatrixWebhookMode:
    # Webhook Mode is disabled
    DISABLED = "off"

    # The default webhook mode is to just be set to Matrix
    MATRIX = "matrix"

    # Support the slack webhook plugin
    SLACK = "slack"

    # Support the t2bot webhook plugin
    T2BOT = "t2bot"

    # Support matrix-hookshot generic webhooks
    HOOKSHOT = "hookshot"


# webhook modes are placed into this list for validation purposes
MATRIX_WEBHOOK_MODES = (
    MatrixWebhookMode.DISABLED,
    MatrixWebhookMode.MATRIX,
    MatrixWebhookMode.SLACK,
    MatrixWebhookMode.T2BOT,
    MatrixWebhookMode.HOOKSHOT,
)


class NotifyMatrix(NotifyBase):
    """A wrapper for Matrix Notifications."""

    # The default descriptive name associated with the Notification
    service_name = "Matrix"

    # The services URL
    service_url = "https://matrix.org/"

    # The default protocol
    protocol = "matrix"

    # The default secure protocol
    secure_protocol = "matrixs"

    # Support Attachments
    attachment_support = True

    # A URL that takes you to the setup/help of the specific protocol
    setup_url = "https://appriseit.com/services/matrix/"

    # Allows the user to specify the NotifyImageSize object
    image_size = NotifyImageSize.XY_32

    # The maximum allowable characters allowed in the body per message
    # https://spec.matrix.org/v1.6/client-server-api/#size-limits
    # The complete event MUST NOT be larger than 65536 bytes, when formatted
    # with the federation event format, including any signatures, and encoded
    # as Canonical JSON.
    #
    # To gracefully allow for some overhead' we'll define a max body length
    # of just slighty lower then the limit of the full message itself.
    body_maxlen = 65000

    # Throttle a wee-bit to avoid thrashing
    request_rate_per_sec = 0.5

    # How many retry attempts we'll make in the event the server asks us to
    # throttle back.
    default_retries = 2

    # The number of micro seconds to wait if we get a 429 error code and
    # the server doesn't remind us how long we should wait for
    default_wait_ms = 1000

    # Our default is to no not use persistent storage beyond in-memory
    # reference
    storage_mode = PersistentStoreMode.AUTO

    # Keep our cache for 20 days
    default_cache_expiry_sec = 60 * 60 * 24 * 20

    # Number of signed_curve25519 one-time keys to generate and upload
    # per batch (both on initial device registration and replenishment).
    default_e2ee_otk_count = 10

    # Replenish the server-side OTK pool when the estimated remaining
    # count drops below this value.  /keys/claim consumes one OTK per
    # device; without replenishment the pool runs dry and subsequent
    # key-shares skip devices that have no OTK available.
    default_e2ee_otk_replenish_threshold = 5

    # Used for server discovery
    discovery_base_key = "__discovery_base"
    discovery_identity_key = "__discovery_identity"

    # Defines how long we cache our discovery for
    discovery_cache_length_sec = 86400

    # Define object templates
    templates = (
        # Targets are ignored when using t2bot/hookshot mode; only a token is
        # required
        "{schema}://{token}",
        "{schema}://{user}@{token}",
        # Matrix Server
        "{schema}://{user}:{password}@{host}/{targets}",
        "{schema}://{user}:{password}@{host}:{port}/{targets}",
        "{schema}://{token}@{host}/{targets}",
        "{schema}://{token}@{host}:{port}/{targets}",
        # Webhook mode
        "{schema}://{user}:{token}@{host}/{targets}",
        "{schema}://{user}:{token}@{host}:{port}/{targets}",
    )

    # Define our template tokens
    template_tokens = dict(
        NotifyBase.template_tokens,
        **{
            "host": {
                "name": _("Hostname"),
                "type": "string",
                "required": True,
            },
            "port": {
                "name": _("Port"),
                "type": "int",
                "min": 1,
                "max": 65535,
            },
            "user": {
                "name": _("Username"),
                "type": "string",
            },
            "password": {
                "name": _("Password"),
                "type": "string",
                "private": True,
            },
            "token": {
                "name": _("Access Token"),
                "type": "string",
                "private": True,
                "map_to": "password",
                "required": True,
            },
            "target_user": {
                "name": _("Target User"),
                "type": "string",
                "prefix": "@",
                "map_to": "targets",
            },
            "target_room_id": {
                "name": _("Target Room ID"),
                "type": "string",
                "prefix": "!",
                "map_to": "targets",
            },
            "target_room_alias": {
                "name": _("Target Room Alias"),
                "type": "string",
                "prefix": "#",
                "map_to": "targets",
            },
            "targets": {
                "name": _("Targets"),
                "type": "list:string",
            },
        },
    )

    # Define our template arguments
    template_args = dict(
        NotifyBase.template_args,
        **{
            "image": {
                "name": _("Include Image"),
                "type": "bool",
                "default": False,
                "map_to": "include_image",
            },
            "discovery": {
                "name": _("Server Discovery"),
                "type": "bool",
                "default": True,
            },
            "hsreq": {
                "name": _("Force Home Server on Room IDs"),
                "type": "bool",
                "default": True,
            },
            "mode": {
                "name": _("Webhook Mode"),
                "type": "choice:string",
                "values": MATRIX_WEBHOOK_MODES,
                "default": MatrixWebhookMode.DISABLED,
            },
            "path": {
                "name": _("Webhook Path"),
                "type": "string",
                "map_to": "webhook_path",
                "default": "/webhook",
            },
            "version": {
                "name": _("Matrix API Verion"),
                "type": "choice:string",
                "values": MATRIX_VERSIONS,
                "default": MatrixVersion.V3,
            },
            "msgtype": {
                "name": _("Message Type"),
                "type": "choice:string",
                "values": MATRIX_MESSAGE_TYPES,
                "default": MatrixMessageType.TEXT,
            },
            "e2ee": {
                "name": _("End-to-End Encryption"),
                "type": "bool",
                "default": True,
            },
            "token": {
                "alias_of": "token",
            },
            "to": {
                "alias_of": "targets",
            },
        },
    )

    def __init__(
        self,
        targets=None,
        mode=None,
        msgtype=None,
        version=None,
        include_image=None,
        discovery=None,
        hsreq=None,
        webhook_path=None,
        e2ee=None,
        **kwargs,
    ):
        """Initialize Matrix Object."""
        super().__init__(**kwargs)

        # Prepare a list of rooms to connect and notify; separate
        # @user DM targets from room identifiers.
        self.rooms = []
        self.users = []
        for _target in parse_list(targets):
            if IS_USER.match(_target):
                self.users.append(_target)
            else:
                self.rooms.append(_target)

        # our home server gets populated after a login/registration
        self.home_server = None

        # our user_id gets populated after a login/registration
        self.user_id = None

        # This gets initialized after a login/registration
        self.access_token = None

        # Our device ID assigned by the Matrix server during login
        self.device_id = None

        # This gets incremented for each request made against the v3 API
        self.transaction_id = 0

        # Lazy-initialized E2EE account (MatrixOlmAccount or None)
        self._e2ee_account = None

        # Place an image inline with the message body
        self.include_image = (
            self.template_args["image"]["default"]
            if include_image is None
            else include_image
        )

        # Prepare Delegate Server Lookup Check
        self.discovery = (
            self.template_args["discovery"]["default"]
            if discovery is None
            else discovery
        )

        # When enabled, room IDs missing a ':homeserver' segment will
        # be treated as legacy identifiers and automatically suffixed
        # with the authenticated homeserver.
        self.hsreq = (
            self.template_args["hsreq"]["default"] if hsreq is None else hsreq
        )

        # Public webhook path used by matrix-hookshot
        self.webhook_path = (
            self.template_args["path"]["default"]
            if not isinstance(webhook_path, str) or not webhook_path.strip()
            else webhook_path.strip()
        )
        if not self.webhook_path.startswith("/"):
            self.webhook_path = f"/{self.webhook_path}"
        self.webhook_path = self.webhook_path.rstrip("/") or "/"

        # End-to-end encryption (server mode only; requires cryptography)
        self.e2ee = (
            self.template_args["e2ee"]["default"]
            if e2ee is None
            else parse_bool(e2ee)
        )

        # Setup our mode
        self.mode = (
            self.template_args["mode"]["default"]
            if not isinstance(mode, str)
            else mode.lower()
        )
        if self.mode and self.mode not in MATRIX_WEBHOOK_MODES:
            msg = f"The mode specified ({mode}) is invalid."
            self.logger.warning(msg)
            raise TypeError(msg)

        # Setup our version
        self.version = (
            self.template_args["version"]["default"]
            if not isinstance(version, str)
            else version
        )
        if self.version not in MATRIX_VERSIONS:
            msg = f"The version specified ({version}) is invalid."
            self.logger.warning(msg)
            raise TypeError(msg)

        # Setup our message type
        self.msgtype = (
            self.template_args["msgtype"]["default"]
            if not isinstance(msgtype, str)
            else msgtype.lower()
        )
        if self.msgtype and self.msgtype not in MATRIX_MESSAGE_TYPES:
            msg = f"The msgtype specified ({msgtype}) is invalid."
            self.logger.warning(msg)
            raise TypeError(msg)

        if self.mode == MatrixWebhookMode.T2BOT:
            # t2bot configuration requires that a webhook id is specified
            self.access_token = validate_regex(
                self.password, r"^[a-z0-9]{64}$", "i"
            )
            if not self.access_token:
                msg = (
                    "An invalid T2Bot/Matrix Webhook ID "
                    f"({self.password}) was specified."
                )
                self.logger.warning(msg)
                raise TypeError(msg)

        elif not is_hostname(self.host):
            msg = f"An invalid Matrix Hostname ({self.host}) was specified"
            self.logger.warning(msg)
            raise TypeError(msg)

        else:
            # Verify port if specified
            if self.port is not None and not (
                isinstance(self.port, int)
                and self.port >= self.template_tokens["port"]["min"]
                and self.port <= self.template_tokens["port"]["max"]
            ):
                msg = f"An invalid Matrix Port ({self.port}) was specified"
                self.logger.warning(msg)
                raise TypeError(msg)

        if self.mode != MatrixWebhookMode.DISABLED:
            # Discovery only works when we're not using webhooks
            self.discovery = False

        #
        # Initialize from cache if present
        #
        if self.mode != MatrixWebhookMode.T2BOT:
            # our home server gets populated after a login/registration
            self.home_server = self.store.get("home_server")

            # our user_id gets populated after a login/registration
            self.user_id = self.store.get("user_id")

            # This gets initialized after a login/registration
            self.access_token = self.store.get("access_token")

            # Device ID assigned by server
            self.device_id = self.store.get("device_id")

            # Older cache entries may have user_id/access_token persisted
            # without home_server. Recover it from @user:homeserver so room
            # aliases do not degrade into '#room:None'.
            if not self.home_server and self.user_id:
                parts = self.user_id.split(":", 1)
                if len(parts) == 2:
                    self.home_server = parts[1]

        # This gets incremented for each request made against the v3 API
        self.transaction_id = (
            0 if not self.access_token else self.store.get("transaction_id", 0)
        )

        # Restore E2EE account from store if available
        if self.e2ee and MATRIX_E2EE_SUPPORT:
            acct_data = self.store.get("e2ee_account")
            if acct_data:
                with contextlib.suppress(Exception):
                    self._e2ee_account = MatrixOlmAccount.from_dict(acct_data)

    def send(self, body, title="", notify_type=NotifyType.INFO, **kwargs):
        """Perform Matrix Notification."""

        # Call the _send_ function applicable to whatever mode we're in
        # - calls _send_webhook_notification if the mode variable is set
        # - calls _send_server_notification if the mode variable is not set
        return getattr(
            self,
            "_send_{}_notification".format(
                "webhook"
                if self.mode != MatrixWebhookMode.DISABLED
                else "server"
            ),
        )(body=body, title=title, notify_type=notify_type, **kwargs)

    def _send_webhook_notification(
        self, body, title="", notify_type=NotifyType.INFO, **kwargs
    ):
        """Perform Matrix Notification as a webhook."""
        pass

    def _slack_webhook_payload(
        self, body, title="", notify_type=NotifyType.INFO, **kwargs
    ):
        """Format the payload for a Slack based message."""
        pass

    def _matrix_webhook_payload(
        self, body, title="", notify_type=NotifyType.INFO, **kwargs
    ):
        """Format the payload for a Matrix based message."""
        pass

    def _t2bot_webhook_payload(
        self, body, title="", notify_type=NotifyType.INFO, **kwargs
    ):
        """Format the payload for a T2Bot Matrix based messages."""
        pass

    def _hookshot_webhook_payload(
        self, body, title="", notify_type=NotifyType.INFO, **kwargs
    ):
        """Format the payload for a matrix-hookshot webhook."""
        pass

    def _send_server_notification(
        self,
        body,
        title="",
        notify_type=NotifyType.INFO,
        attach=None,
        **kwargs,
    ):
        """Perform Direct Matrix Server Notification (no webhook)"""
        pass

    def _send_attachments(self, attach):
        """Posts all of the provided attachments."""

        payloads = []

        for attachment in attach:
            if not attachment:
                # invalid attachment (bad file)
                return False

            if (
                not IS_IMAGE.match(attachment.mimetype)
                and self.version == MatrixVersion.V2
            ):
                # unsuppored at this time
                continue

            postokay, response, _ = self._fetch(
                "/upload", attachment=attachment
            )
            if not (postokay and isinstance(response, dict)):
                # Failed to perform upload
                return False

            # If we get here, we'll have a response that looks like:
            # {
            #     "content_uri": "mxc://example.com/a-unique-key"
            # }

            if self.version == MatrixVersion.V3:
                # Prepare our payload
                is_image = IS_IMAGE.match(attachment.mimetype)
                payloads.append(
                    {
                        "body": attachment.name,
                        "info": {
                            "mimetype": attachment.mimetype,
                            "size": len(attachment),
                        },
                        "msgtype": "m.image" if is_image else "m.file",
                        "url": response.get("content_uri"),
                    }
                )
                if not is_image:
                    # Setup `m.file'
                    payloads[-1]["filename"] = attachment.name

            else:
                # Prepare our payload
                payloads.append(
                    {
                        "info": {
                            "mimetype": attachment.mimetype,
                        },
                        "msgtype": "m.image",
                        "body": "tta.webp",
                        "url": response.get("content_uri"),
                    }
                )

        return payloads

    def _register(self):
        """Register with the service if possible."""
        pass

    def _login(self):
        """Acquires the matrix token required for making future requests.

        If we fail we return False, otherwise we return True
        """
        pass

    def _whoami(self):
        """Resolve user_id, device_id, and home_server via GET /account/whoami.

        Called when a raw access token is supplied (no login flow), so
        the server never returned these identifiers directly.  Results
        are cached in the persistent store for future calls.

        Returns True on success, False otherwise.
        """
        ok, response, _ = self._fetch(
            "/account/whoami", payload=None, method="GET"
        )
        if not (ok and isinstance(response, dict)):
            return False

        self.user_id = response.get("user_id") or self.user_id
        self.device_id = response.get("device_id") or self.device_id

        # Extract home_server from user_id (@localpart:homeserver) so that
        # DM targets without an explicit homeserver resolve correctly.
        if self.user_id and not self.home_server:
            parts = self.user_id.split(":", 1)
            if len(parts) == 2:
                self.home_server = parts[1]

        if self.user_id:
            self.store.set(
                "user_id",
                self.user_id,
                expires=self.default_cache_expiry_sec,
            )
        if self.device_id:
            self.store.set(
                "device_id",
                self.device_id,
                expires=self.default_cache_expiry_sec,
            )
        if self.home_server:
            self.store.set(
                "home_server",
                self.home_server,
                expires=self.default_cache_expiry_sec,
            )
        return True

    def _logout(self):
        """Relinquishes token from remote server."""
        pass

    def _room_join(self, room):
        """Joins a matrix room if we're not already in it.

        Otherwise it attempts to create it if it doesn't exist and
        always returns the room_id if it was successful, otherwise it
        returns None
        """
        pass

    def _room_create(self, room):
        """Creates a matrix room and return it's room_id if successful
        otherwise None is returned."""
        pass

    def _joined_rooms(self):
        """Returns a list of the current rooms the logged in user is a
        part of."""
        pass

    def _room_id(self, room):
        """Get room id from its alias.
        Args:
            room (str): The room alias name.

        Returns:
            returns the room id if it can, otherwise it returns None
        """
        pass

    def _fetch(
        self,
        path,
        payload=None,
        params=None,
        attachment=None,
        method="POST",
        url_override=None,
        ok_status=None,
    ):
        """Wrapper to request.post() to manage it's response better and
        make the send() function cleaner and easier to maintain.

        This function always returns a 3-tuple:
            (success, response, status_code)

        The response is a dict when JSON is parseable, otherwise an empty
        dict. The status_code defaults to 500 on local failures.

        *ok_status* is an optional collection of additional HTTP status codes
        to treat as success (no warning logged).  Use it for calls where a
        non-200 response is expected and meaningful, e.g. 404 on a state-event
        probe that returns "not found" = "feature not enabled".
        """

        # Define our headers
        if params is None:
            params = {}
        headers = {
            "User-Agent": self.app_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        if self.access_token is not None:
            headers["Authorization"] = f"Bearer {self.access_token}"

        # Server Discovery / Well-known URI
        if url_override:
            url = url_override

        else:
            try:
                url = self.base_url

            except MatrixDiscoveryException:
                # Discovery failed; we're done
                return (False, {}, requests.codes.internal_server_error)

        # Default return status code
        status_code = requests.codes.internal_server_error

        if path == "/upload":
            if self.version == MatrixVersion.V3:
                url += MATRIX_V3_MEDIA_PATH + path

            else:
                url += MATRIX_V2_MEDIA_PATH + path

            params.update({"filename": attachment.name})
            with open(attachment.path, "rb") as fp:
                payload = fp.read()

            # Update our content type
            headers["Content-Type"] = attachment.mimetype

        elif not url_override:
            if self.version == MatrixVersion.V3:
                url += MATRIX_V3_API_PATH + path

            else:
                url += MATRIX_V2_API_PATH + path

        # Our response object
        response = {}

        # fetch function
        fn = (
            requests.post
            if method == "POST"
            else (requests.put if method == "PUT" else requests.get)
        )

        # Always call throttle before any remote server i/o is made
        self.throttle()

        # Define how many attempts we'll make if we get caught in a
        # throttle event
        retries = self.default_retries if self.default_retries > 0 else 1
        while retries > 0:
            # Decrement our throttle retry count
            retries -= 1

            self.logger.debug(
                "Matrix {} URL: {} (cert_verify={!r})".format(
                    (
                        "POST"
                        if method == "POST"
                        else ("PUT" if method == "PUT" else "GET")
                    ),
                    url,
                    self.verify_certificate,
                )
            )
            self.logger.debug(f"Matrix Payload: {payload!s}")

            # Initialize our response object
            r = None

            try:
                r = fn(
                    url,
                    data=dumps(payload) if not attachment else payload,
                    params=params if params else None,
                    headers=headers,
                    verify=self.verify_certificate,
                    timeout=self.request_timeout,
                )

                # Store status code
                status_code = r.status_code

                self.logger.debug(
                    "Matrix Response: code={}, {}".format(
                        r.status_code, r.content
                    )
                )
                response = loads(r.content)

                if r.status_code == requests.codes.too_many_requests:
                    wait_ms = self.default_wait_ms
                    try:
                        wait_ms = response["retry_after_ms"]

                    except KeyError:
                        try:
                            errordata = response["error"]
                            wait_ms = errordata["retry_after_ms"]
                        except KeyError:
                            pass

                    self.logger.warning(
                        "Matrix server requested we throttle back "
                        "{}ms; retries left {}.".format(wait_ms, retries)
                    )
                    self.logger.debug(f"Response Details:\r\n{r.content}")

                    # Throttle for specified wait
                    self.throttle(wait=wait_ms / 1000)

                    # Try again
                    continue

                elif r.status_code != requests.codes.ok:
                    # We had a problem
                    if ok_status and r.status_code in ok_status:
                        # Caller declared this status code acceptable
                        # (e.g. 404 on a state-event probe).  Return
                        # failure tuple silently -- no warning logged.
                        return (False, response, status_code)

                    status_str = NotifyMatrix.http_response_code_lookup(
                        r.status_code, MATRIX_HTTP_ERROR_MAP
                    )

                    self.logger.warning(
                        "Failed to handshake with Matrix server: "
                        "{}{}error={}.".format(
                            status_str,
                            ", " if status_str else "",
                            r.status_code,
                        )
                    )

                    self.logger.debug(f"Response Details:\r\n{r.content}")

                    # Return; we're done
                    return (False, response, status_code)

            except (AttributeError, TypeError, ValueError):
                # This gets thrown if we can't parse our JSON Response
                #  - ValueError = r.content is Unparsable
                #  - TypeError = r.content is None
                #  - AttributeError = r is None
                self.logger.warning("Invalid response from Matrix server.")
                self.logger.debug(
                    "Response Details:\r\n%r",
                    b"" if not r else (r.content or b""),
                )
                return (False, {}, status_code)

            except (
                requests.TooManyRedirects,
                requests.RequestException,
            ) as e:
                self.logger.warning(
                    "A Connection error occurred while registering "
                    "with Matrix server."
                )
                self.logger.debug("Socket Exception: %s", e)
                # Return; we're done
                return (False, response, status_code)

            except OSError as e:
                self.logger.warning(
                    "An I/O error occurred while reading {}.".format(
                        attachment.name if attachment else "unknown file"
                    )
                )
                self.logger.debug("I/O Exception: %s", e)
                return (False, {}, status_code)

            return (True, response, status_code)

        # If we get here, we ran out of retries
        return (False, {}, status_code)

    # ---------------------------------------------------------------
    # E2EE helpers
    # ---------------------------------------------------------------

    def _e2ee_room_encrypted(self, room_id):
        """Return ``True`` if *room_id* has E2EE enabled on the server.

        The result is cached in the persistent store so subsequent sends
        to the same room do not issue additional network requests.
        """
        pass

    def _e2ee_setup(self):
        """Ensure the E2EE device account exists and keys are uploaded.

        Creates a new :class:`MatrixOlmAccount` if one does not yet
        exist in the persistent store, then calls
        :meth:`_e2ee_upload_keys` if the server has not yet received
        our device keys for the current access token.

        Returns ``True`` on success, ``False`` on failure.
        """
        pass

    def _e2ee_upload_keys(self):
        """POST device keys to ``/_matrix/client/v3/keys/upload``."""
        pass

    def _e2ee_replenish_otks(self, claimed_count=0, skipped_no_otk=0):
        """Top up the server-side OTK pool after a ``/keys/claim`` event.

        Parameters:
          claimed_count   -- number of OTKs successfully consumed by the
                             preceding ``/keys/claim`` (= ``built_count``
                             from :meth:`_e2ee_share_room_key`)
          skipped_no_otk  -- devices that were skipped because the server
                             returned no OTK for them (pool already dry)

        A replenishment upload is issued when any of the following is true:

        - ``skipped_no_otk > 0``: the pool was already depleted during
          the current claim -- top up immediately so the next key share
          can reach those devices.
        - estimated remaining OTKs after claim <
          ``default_e2ee_otk_replenish_threshold``: pool is running low.
        - server count was never recorded (unknown state): replenish as a
          precaution.

        Only ``one_time_keys`` is uploaded so the server does not treat
        this as a device re-registration.

        Returns ``True`` on success (or when no top-up was needed),
        ``False`` on network failure (non-fatal -- the preceding send
        already succeeded).
        """
        pass

    def _e2ee_get_megolm(self, room_id):
        """Return the current outbound MegOLM session for *room_id*.

        Creates a new session when none exists or when the existing one
        has reached the rotation threshold.  Also clears the
        ``e2ee_key_shared_*`` flag so the new session key is re-shared.
        """
        pass

    def _e2ee_save_megolm(self, room_id, session):
        """Persist the updated MegOLM session state."""
        pass

    def _e2ee_room_members(self, room_id):
        """Query device keys for all joined members of *room_id*.

        Returns a nested dict::

            {user_id: {device_id: {"curve25519": ..., "ed25519": ...}}}

        Returns ``None`` on HTTP failure, empty dict when the room has
        no members (unlikely but tolerated).
        """
        pass

    def _e2ee_share_room_key(self, room_id, session):
        """Send the MegOLM session key to all devices in *room_id*.

        Flow:
          1. Fetch joined-member device keys via /keys/query
          2. Claim one-time keys via /keys/claim
          3. Create outbound Olm sessions and encrypt the room-key event
          4. Deliver via PUT /sendToDevice/m.room.encrypted/{txnId}

        Returns ``True`` on success (partial device failures are
        tolerated), ``False`` only when a critical step fails.
        """
        pass

    def _e2ee_send_to_room(self, room_id, body, title, notify_type):
        """Encrypt and send one message to *room_id* via MegOLM.

        Shares the MegOLM session key with room members when the
        session is new or has just been rotated.
        Returns ``True`` on success, ``False`` on failure.
        """
        pass

    def _e2ee_send_attachment(self, attachment, room_id, session):
        """Encrypt *attachment* and deliver it to *room_id* via MegOLM.

        Steps:
        1. Read the file into memory and encrypt with AES-256-CTR.
        2. Upload the ciphertext to the media server (content_uri).
        3. Build an ``m.room.message`` inner event whose ``file`` field
           carries the EncryptedFile metadata (key + iv + sha256).
        4. Encrypt the inner event with MegOLM and PUT to the room.

        Returns ``True`` on success, ``False`` on any failure.
        """
        pass

    def _dm_room_find_or_create(self, user):
        """Resolve *user* (``@localpart`` or ``@localpart:homeserver``)
        to a Matrix room ID suitable for direct messaging.

        Lookup order:
        1. Persistent-store cache.
        2. ``GET /user/{selfId}/account_data/m.direct`` -- check whether
           an existing DM room already exists for this user.
        3. ``POST /createRoom`` with ``is_direct=true`` and an invite for
           the target user.  The ``m.direct`` account-data entry is then
           updated so other clients also recognise the room as a DM.

        Returns the room ID string on success, or ``None`` on failure.
        """
        pass

    # ---------------------------------------------------------------
    # Destructor / URL / parse
    # ---------------------------------------------------------------

    def __del__(self):
        """Ensure we relinquish our token."""
        if self.mode == MatrixWebhookMode.T2BOT:
            # nothing to do
            return

        if self.store.mode != PersistentStoreMode.MEMORY:
            # We no longer have to log out as we have persistant storage
            # to re-use our credentials with
            return

        if (
            self.access_token is not None
            and self.access_token == self.password
            and not self.user
        ):
            return

        # Best-effort cleanup only
        with contextlib.suppress(Exception):
            self._logout()

    @property
    def url_identifier(self):
        """Returns all of the identifiers that make this URL unique from
        another simliar one.

        Targets or end points should never be identified here.
        """
        pass

    @staticmethod
    def runtime_deps():
        """Return runtime dependency package names.

        E2EE support requires the `cryptography` package.
        """
        pass

    def url(self, privacy=False, *args, **kwargs):
        """Returns the URL built dynamically based on specified
        arguments."""

        # Define any URL parameters
        params = {
            "image": "yes" if self.include_image else "no",
            "mode": self.mode,
            "version": self.version,
            "msgtype": self.msgtype,
            "discovery": "yes" if self.discovery else "no",
            "hsreq": "yes" if self.hsreq else "no",
        }

        if self.mode == MatrixWebhookMode.HOOKSHOT:
            params["path"] = self.webhook_path

        if not self.e2ee:
            params["e2ee"] = "no"

        # Extend our parameters
        params.update(self.url_parameters(privacy=privacy, *args, **kwargs))

        auth = ""
        if self.mode != MatrixWebhookMode.T2BOT:
            # Determine Authentication
            if self.user and self.password:
                auth = "{user}:{password}@".format(
                    user=NotifyMatrix.quote(self.user, safe=""),
                    password=self.pprint(
                        self.password,
                        privacy,
                        mode=PrivacyMode.Secret,
                        safe="",
                    ),
                )

            elif self.user or self.password:
                auth = "{value}@".format(
                    value=NotifyMatrix.quote(
                        self.user if self.user else self.password, safe=""
                    ),
                )

        return "{schema}://{auth}{hostname}{port}/{rooms}?{params}".format(
            schema=(self.secure_protocol if self.secure else self.protocol),
            auth=auth,
            hostname=(
                NotifyMatrix.quote(self.host, safe="")
                if self.mode != MatrixWebhookMode.T2BOT
                else self.pprint(self.access_token, privacy, safe="")
            ),
            port=("" if not self.port else f":{self.port}"),
            rooms=NotifyMatrix.quote("/".join(self.rooms + self.users)),
            params=NotifyMatrix.urlencode(params),
        )

    def __len__(self):
        """Returns the number of targets associated with this
        notification."""
        targets = len(self.rooms) + len(self.users)
        return targets if targets > 0 else 1

    @staticmethod
    def parse_url(url):
        """Parses the URL and returns enough arguments that can allow us
        to re-instantiate this object."""
        results = NotifyBase.parse_url(url, verify_host=False)
        if not results:
            # We're done early as we couldn't load the results
            return results

        if not results.get("host"):
            return None

        # Get our rooms
        results["targets"] = NotifyMatrix.split_path(results["fullpath"])

        # Support the 'to' variable so that we can support rooms this
        # way too.  The 'to' makes it easier to use yaml configuration
        if "to" in results["qsd"] and len(results["qsd"]["to"]):
            results["targets"] += NotifyMatrix.parse_list(results["qsd"]["to"])

        # Boolean to include an image or not
        results["include_image"] = parse_bool(
            results["qsd"].get(
                "image",
                NotifyMatrix.template_args["image"]["default"],
            )
        )

        # Boolean to perform a server discovery
        results["discovery"] = parse_bool(
            results["qsd"].get(
                "discovery",
                NotifyMatrix.template_args["discovery"]["default"],
            )
        )

        # Boolean to enforce ':homeserver' on room IDs when missing
        results["hsreq"] = parse_bool(
            results["qsd"].get(
                "hsreq",
                NotifyMatrix.template_args["hsreq"]["default"],
            )
        )

        if "path" in results["qsd"]:
            results["webhook_path"] = NotifyMatrix.unquote(
                results["qsd"]["path"]
            )

        # E2EE flag
        if "e2ee" in results["qsd"]:
            results["e2ee"] = parse_bool(results["qsd"]["e2ee"])

        # Get our mode
        results["mode"] = results["qsd"].get("mode")

        # t2bot detection... look for just a hostname, and/or just a
        # user/host if we match this; we can go ahead and set the mode
        # (but only if it was otherwise not set)
        if (
            results["mode"] is None
            and not results["password"]
            and not results["targets"]
        ):
            # Default mode to t2bot
            results["mode"] = MatrixWebhookMode.T2BOT

        if (
            results["mode"]
            and results["mode"].lower() == MatrixWebhookMode.T2BOT
        ):
            # unquote our hostname and pass it in as the password/token
            results["password"] = NotifyMatrix.unquote(results["host"])

        # Support the message type keyword
        if "msgtype" in results["qsd"] and len(results["qsd"]["msgtype"]):
            results["msgtype"] = NotifyMatrix.unquote(
                results["qsd"]["msgtype"]
            )

        # Support the use of the token= keyword
        if "token" in results["qsd"] and len(results["qsd"]["token"]):
            results["password"] = NotifyMatrix.unquote(results["qsd"]["token"])

        elif not results["password"] and results["user"]:
            # swap
            results["password"] = results["user"]
            results["user"] = None

        # Support the use of the version= or v= keyword
        if "version" in results["qsd"] and len(results["qsd"]["version"]):
            results["version"] = NotifyMatrix.unquote(
                results["qsd"]["version"]
            )

        elif "v" in results["qsd"] and len(results["qsd"]["v"]):
            results["version"] = NotifyMatrix.unquote(results["qsd"]["v"])

        return results

    @staticmethod
    def parse_native_url(url):
        """
        Support https://webhooks.t2bot.io/api/v1/matrix/hook/WEBHOOK_TOKEN/
        """

        result = re.match(
            r"^https?://webhooks\.t2bot\.io/api/v[0-9]+/matrix/hook/"
            r"(?P<webhook_token>[A-Z0-9_-]+)/?"
            r"(?P<params>\?.+)?$",
            url,
            re.I,
        )

        if result:
            mode = f"mode={MatrixWebhookMode.T2BOT}"

            return NotifyMatrix.parse_url(
                "{schema}://{webhook_token}/{params}".format(
                    schema=NotifyMatrix.secure_protocol,
                    webhook_token=result.group("webhook_token"),
                    params=(
                        f"?{mode}"
                        if not result.group("params")
                        else "{}&{}".format(result.group("params"), mode)
                    ),
                )
            )

        return None

    def server_discovery(self):
        """
        Home Server Discovery as documented here:
           https://spec.matrix.org/v1.11/client-server-api/#well-known-uri
        """
        pass

    @property
    def base_url(self):
        """Returns the base_url if known."""
        pass

    @property
    def identity_url(self):
        """Returns the identity_url if known."""
        pass
