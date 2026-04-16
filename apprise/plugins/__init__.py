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

import copy
import os

from ..common import (
    NOTIFY_IMAGE_SIZES,
    NOTIFY_TYPES,
    NotifyImageSize,
    NotifyType,
)
from ..locale import LazyTranslation, gettext_lazy as _
from ..logger import logger
from ..manager_plugins import NotificationManager
from ..utils.cwe312 import cwe312_url
from ..utils.parse import GET_SCHEMA_RE, parse_list

# Used for testing
from .base import NotifyBase

# Grant access to our Notification Manager Singleton
N_MGR = NotificationManager()

__all__ = [
    "NOTIFY_IMAGE_SIZES",
    "NOTIFY_TYPES",
    "NotifyBase",
    # Reference
    "NotifyImageSize",
    "NotifyType",
    # Tokenizer
    "url_to_dict",
]


def _sanitize_token(tokens, default_delimiter):
    """This is called by the details() function and santizes the output by
    populating expected and consistent arguments if they weren't otherwise
    specified."""
    pass


def details(plugin):
    """Provides templates that can be used by developers to build URLs
    dynamically.

    If a list of templates is provided, then they will be used over the default
    value.

    If a list of tokens are provided, then they will over-ride any additional
    settings built from this script and/or will be appended to them afterwards.
    """
    pass


def requirements(plugin):
    """Provides a list of packages and its requirement details."""
    pass


def url_to_dict(url, secure_logging=True):
    """Takes an apprise URL and returns the tokens associated with it if they
    can be acquired based on the plugins available.

    None is returned if the URL could not be parsed, otherwise the tokens are
    returned.

    These tokens can be loaded into apprise through it's add() function.
    """

    # swap hash (#) tag values with their html version
    url_ = url.replace("/#", "/%23")

    # CWE-312 (Secure Logging) Handling
    loggable_url = url if not secure_logging else cwe312_url(url)

    # Attempt to acquire the schema at the very least to allow our plugins to
    # determine if they can make a better interpretation of a URL geared for
    # them.
    schema = GET_SCHEMA_RE.match(url_)
    if schema is None:
        # Not a valid URL; take an early exit
        logger.error(f"Unsupported URL: {loggable_url}")
        return None

    # Ensure our schema is always in lower case
    schema = schema.group("schema").lower()
    if schema not in N_MGR:
        # Give the user the benefit of the doubt that the user may be using
        # one of the URLs provided to them by their notification service.
        # Before we fail for good, just scan all the plugins that support the
        # native_url() parse function
        results = None
        for plugin in N_MGR.plugins():
            results = plugin.parse_native_url(url_)
            if results:
                break

        if not results:
            logger.error(f"Unparseable URL {loggable_url}")
            return None

        logger.trace(
            "URL {} unpacked as:{}{}".format(
                url,
                os.linesep,
                os.linesep.join([f'{k}="{v}"' for k, v in results.items()]),
            )
        )

    else:
        # Parse our url details of the server object as dictionary
        # containing all of the information parsed from our URL
        results = N_MGR[schema].parse_url(url_)
        if not results:
            logger.error(
                f"Unparseable {N_MGR[schema].service_name} URL {loggable_url}"
            )
            return None

        logger.trace(
            "{} URL {} unpacked as:{}{}".format(
                N_MGR[schema].service_name,
                url,
                os.linesep,
                os.linesep.join([f'{k}="{v}"' for k, v in results.items()]),
            )
        )

    # Return our results
    return results
