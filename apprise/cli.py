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

import logging
import os
from os.path import exists, isfile
import platform
import re
import shutil
import sys
import textwrap

import click

from . import (
    Apprise,
    AppriseAsset,
    AppriseConfig,
    PersistentStore,
    __copyright__,
    __license__,
    __title__,
    __version__,
)
from .common import (
    NOTIFY_FORMATS,
    NOTIFY_TYPES,
    PERSISTENT_STORE_MODES,
    ContentLocation,
    NotifyFormat,
    NotifyType,
    PersistentStoreMode,
    PersistentStoreState,
)
from .logger import logger
from .utils.disk import bytes_to_str, dir_size, path_decode
from .utils.parse import parse_list

# By default we allow looking 1 level down recursively in Apprise configuration
# files.
DEFAULT_RECURSION_DEPTH = 1

# Default number of days to prune persistent storage
DEFAULT_STORAGE_PRUNE_DAYS = int(
    os.environ.get("APPRISE_STORAGE_PRUNE_DAYS", 30)
)

# The default URL ID Length
DEFAULT_STORAGE_UID_LENGTH = int(
    os.environ.get("APPRISE_STORAGE_UID_LENGTH", 8)
)

# Defines the environment variable to parse if defined. This is ONLY
# Referenced if:
# - No Configuration Files were found/loaded/specified
# - No URLs were provided directly into the CLI Call
DEFAULT_ENV_APPRISE_URLS = "APPRISE_URLS"

# Defines the override path for the configuration files read
DEFAULT_ENV_APPRISE_CONFIG_PATH = "APPRISE_CONFIG_PATH"

# Defines the override path for the plugins to load
DEFAULT_ENV_APPRISE_PLUGIN_PATH = "APPRISE_PLUGIN_PATH"

# Defines the override path for the persistent storage
DEFAULT_ENV_APPRISE_STORAGE_PATH = "APPRISE_STORAGE_PATH"

# Defines our click context settings adding -h to the additional options that
# can be specified to get the help menu to come up
CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}

# Define our default configuration we use if nothing is otherwise specified
DEFAULT_CONFIG_PATHS = (
    # Legacy Path Support
    "~/.apprise",
    "~/.apprise.conf",
    "~/.apprise.yml",
    "~/.apprise.yaml",
    "~/.config/apprise",
    "~/.config/apprise.conf",
    "~/.config/apprise.yml",
    "~/.config/apprise.yaml",
    # Plugin Support Extended Directory Search Paths
    "~/.apprise/apprise",
    "~/.apprise/apprise.conf",
    "~/.apprise/apprise.yml",
    "~/.apprise/apprise.yaml",
    "~/.config/apprise/apprise",
    "~/.config/apprise/apprise.conf",
    "~/.config/apprise/apprise.yml",
    "~/.config/apprise/apprise.yaml",
    # Global Configuration File Support
    "/etc/apprise",
    "/etc/apprise.yml",
    "/etc/apprise.yaml",
    "/etc/apprise/apprise",
    "/etc/apprise/apprise.conf",
    "/etc/apprise/apprise.yml",
    "/etc/apprise/apprise.yaml",
)

# Define our paths to search for plugins
DEFAULT_PLUGIN_PATHS = (
    "~/.apprise/plugins",
    "~/.config/apprise/plugins",
    # Global Plugin Support
    "/var/lib/apprise/plugins",
)


#
# General Options and Defaults
#
DEFAULT_NOTIFY_TYPE = NotifyType.INFO

NOTIFY_TYPE_CHOICES: tuple[NotifyType, ...] = (
    NotifyType.INFO,
    NotifyType.SUCCESS,
    NotifyType.WARNING,
    NotifyType.FAILURE,
)

DEFAULT_NOTIFY_FORMAT = NotifyFormat.TEXT

NOTIFY_FORMAT_CHOICES: tuple[NotifyFormat, ...] = (
    NotifyFormat.TEXT,
    NotifyFormat.MARKDOWN,
    NotifyFormat.HTML,
)

#
# Persistent Storage
#
DEFAULT_STORAGE_PATH = "~/.local/share/apprise/cache"

# Storage Mode
DEFAULT_STORAGE_MODE = PersistentStoreMode.AUTO

# Create an ordered list of options (first is default)
PERSISTENT_STORE_MODE_CHOICES: tuple[PersistentStoreMode, ...] = (
    PersistentStoreMode.AUTO,
    PersistentStoreMode.FLUSH,
    PersistentStoreMode.MEMORY,
)

# Detect Windows
if platform.system() == "Windows":
    # Default Config Search Path for Windows Users
    DEFAULT_CONFIG_PATHS = (
        "%APPDATA%\\Apprise\\apprise",
        "%APPDATA%\\Apprise\\apprise.conf",
        "%APPDATA%\\Apprise\\apprise.yml",
        "%APPDATA%\\Apprise\\apprise.yaml",
        "%LOCALAPPDATA%\\Apprise\\apprise",
        "%LOCALAPPDATA%\\Apprise\\apprise.conf",
        "%LOCALAPPDATA%\\Apprise\\apprise.yml",
        "%LOCALAPPDATA%\\Apprise\\apprise.yaml",
        #
        # Global Support
        #
        # C:\ProgramData\Apprise
        "%ALLUSERSPROFILE%\\Apprise\\apprise",
        "%ALLUSERSPROFILE%\\Apprise\\apprise.conf",
        "%ALLUSERSPROFILE%\\Apprise\\apprise.yml",
        "%ALLUSERSPROFILE%\\Apprise\\apprise.yaml",
        # C:\Program Files\Apprise
        "%PROGRAMFILES%\\Apprise\\apprise",
        "%PROGRAMFILES%\\Apprise\\apprise.conf",
        "%PROGRAMFILES%\\Apprise\\apprise.yml",
        "%PROGRAMFILES%\\Apprise\\apprise.yaml",
        # C:\Program Files\Common Files
        "%COMMONPROGRAMFILES%\\Apprise\\apprise",
        "%COMMONPROGRAMFILES%\\Apprise\\apprise.conf",
        "%COMMONPROGRAMFILES%\\Apprise\\apprise.yml",
        "%COMMONPROGRAMFILES%\\Apprise\\apprise.yaml",
    )

    # Default Plugin Search Path for Windows Users
    DEFAULT_PLUGIN_PATHS = (
        "%APPDATA%\\Apprise\\plugins",
        "%LOCALAPPDATA%\\Apprise\\plugins",
        #
        # Global Support
        #
        # C:\ProgramData\Apprise\plugins
        "%ALLUSERSPROFILE%\\Apprise\\plugins",
        # C:\Program Files\Apprise\plugins
        "%PROGRAMFILES%\\Apprise\\plugins",
        # C:\Program Files\Common Files
        "%COMMONPROGRAMFILES%\\Apprise\\plugins",
    )

    #
    # Persistent Storage
    #
    DEFAULT_STORAGE_PATH = "%APPDATA%/Apprise/cache"


class PersistentStorageMode:
    """Persistent Storage Modes."""

    # List all detected configuration loaded
    LIST = "list"

    # Prune persistent storage based on age
    PRUNE = "prune"

    # Reset all (regardless of age)
    CLEAR = "clear"


# Define the types in a list for validation purposes
PERSISTENT_STORAGE_MODES = (
    PersistentStorageMode.LIST,
    PersistentStorageMode.PRUNE,
    PersistentStorageMode.CLEAR,
)

if os.environ.get("APPRISE_STORAGE_PATH", "").strip():
    # Override Default Storage Path
    DEFAULT_STORAGE_PATH = os.environ.get("APPRISE_STORAGE_PATH")


def print_version_msg():
    """Prints version message when -V or --version is specified."""
    pass


class CustomHelpCommand(click.Command):
    def format_help(self, ctx, formatter):
        pass


@click.command(context_settings=CONTEXT_SETTINGS, cls=CustomHelpCommand)
@click.option(
    "--body",
    "-b",
    default=None,
    type=str,
    help=(
        "Specify the message body. If no body is specified then "
        "content is read from <stdin>."
    ),
)
@click.option(
    "--title",
    "-t",
    default=None,
    type=str,
    help="Specify the message title. This field is completely optional.",
)
@click.option(
    "--plugin-path",
    "-P",
    default=None,
    type=str,
    multiple=True,
    metavar="PATH",
    help="Specify one or more plugin paths to scan.",
)
@click.option(
    "--storage-path",
    "-S",
    default=DEFAULT_STORAGE_PATH,
    type=str,
    metavar="PATH",
    help=(
        "Specify the path to the persistent storage location "
        f"(default={DEFAULT_STORAGE_PATH})."
    ),
)
@click.option(
    "--storage-prune-days",
    "-SPD",
    default=DEFAULT_STORAGE_PRUNE_DAYS,
    type=int,
    help=(
        "Define the number of days the storage prune should run using."
        " Setting this to zero (0) will eliminate all accumulated content. By"
        f" default this value is {DEFAULT_STORAGE_PRUNE_DAYS} days."
    ),
)
@click.option(
    "--storage-uid-length",
    "-SUL",
    default=DEFAULT_STORAGE_UID_LENGTH,
    type=int,
    help=(
        "Define the number of unique characters to store persistent cache in."
        f" By default this value is {DEFAULT_STORAGE_UID_LENGTH} characters."
    ),
)
@click.option(
    "--storage-mode",
    "-SM",
    default=DEFAULT_STORAGE_MODE.value,
    type=str,
    metavar="MODE",
    help=(
        "Specify the persistent storage operational mode "
        f"(default={DEFAULT_STORAGE_MODE.value}). "
        'Possible values are: "{}".'.format(
            '", "'.join(mode.value for mode in PERSISTENT_STORE_MODE_CHOICES)
        )
    ),
)
@click.option(
    "--config",
    "-c",
    default=None,
    type=str,
    multiple=True,
    metavar="CONFIG_URL",
    help="Specify one or more configuration locations.",
)
@click.option(
    "--attach",
    "-a",
    default=None,
    type=str,
    multiple=True,
    metavar="ATTACHMENT_URL",
    help="Specify one or more attachments.",
)
@click.option(
    "--notification-type",
    "-n",
    default=DEFAULT_NOTIFY_TYPE.value,
    type=str,
    metavar="TYPE",
    help=(
        f"Specify the message type (default={DEFAULT_NOTIFY_TYPE.value}). "
        'Possible values are: "{}".'.format(
            '", "'.join(nt.value for nt in NOTIFY_TYPE_CHOICES)
        )
    ),
)
@click.option(
    "--input-format",
    "-i",
    default=DEFAULT_NOTIFY_FORMAT.value,
    type=str,
    metavar="FORMAT",
    help=(
        f"Specify the message input format "
        f"(default={DEFAULT_NOTIFY_FORMAT.value}). "
        'Possible values are: "{}".'.format(
            '", "'.join(fmt.value for fmt in NOTIFY_FORMAT_CHOICES)
        )
    ),
)
@click.option(
    "--theme",
    "-T",
    default="default",
    type=str,
    metavar="THEME",
    help="Specify the default theme.",
)
@click.option(
    "--tag",
    "-g",
    default=None,
    type=str,
    multiple=True,
    metavar="TAG",
    help=(
        "Specify one or more tags to filter which services to notify. Use "
        "multiple --tag (-g) entries to match ANY tag. Use comma separators "
        "to require ALL tags (strict match). Omit to notify untagged services "
        'only, or use "all" to notify everything.'
    ),
)
@click.option(
    "--disable-async",
    "-Da",
    is_flag=True,
    help="Send all notifications sequentially",
)
@click.option(
    "--dry-run",
    "-d",
    is_flag=True,
    help=(
        "Perform a trial run but only prints the notification "
        "services to-be triggered to stdout. Notifications are never "
        "sent using this mode."
    ),
)
@click.option(
    "--details",
    "-l",
    is_flag=True,
    help="Prints details about the current services supported by Apprise.",
)
@click.option(
    "--recursion-depth",
    "-R",
    default=DEFAULT_RECURSION_DEPTH,
    type=int,
    help=(
        "The number of recursive import entries that can be "
        "loaded from within Apprise configuration. By default "
        f"this is set to {DEFAULT_RECURSION_DEPTH}."
    ),
)
@click.option(
    "--verbose",
    "-v",
    count=True,
    help=(
        "Makes the operation more talkative. Use multiple v to "
        "increase the verbosity. I.e.: -vvvv"
    ),
)
@click.option(
    "--interpret-escapes",
    "-e",
    is_flag=True,
    help="Enable interpretation of backslash escapes",
)
@click.option(
    "--interpret-emojis",
    "-j",
    is_flag=True,
    help="Enable interpretation of :emoji: definitions",
)
@click.option("--debug", "-D", is_flag=True, help="Debug mode")
@click.option(
    "--version",
    "-V",
    is_flag=True,
    help="Display the apprise version and exit.",
)
@click.argument(
    "urls",
    nargs=-1,
    metavar="SERVER_URL [SERVER_URL2 [SERVER_URL3]]",
)
@click.pass_context
def main(
    ctx,
    body,
    title,
    config,
    attach,
    urls,
    notification_type,
    theme,
    tag,
    input_format,
    dry_run,
    recursion_depth,
    verbose,
    disable_async,
    details,
    interpret_escapes,
    interpret_emojis,
    plugin_path,
    storage_path,
    storage_mode,
    storage_prune_days,
    storage_uid_length,
    debug,
    version,
):
    """Send a notification to all of the specified servers identified by their
    URLs the content provided within the title, body and notification-type.

    For a list of all of the supported services and information on how to use
    them, check out https://github.com/caronc/apprise
    """
    pass
