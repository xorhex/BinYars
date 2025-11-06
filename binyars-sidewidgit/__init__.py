from .binyars import BinYarsSidebarWidgetType
from binaryninjaui import Sidebar
from binaryninja import Settings, Logger, user_plugin_path

from pathlib import Path

import os
import shutil
import json
import platform

logger = Logger(session_id=0, logger_name=__name__)


def get_os_libbinyars():
    os_name = platform.system()
    if os_name == "Windows":
        return "binyars.dll"
    elif os_name == "Linux":
        return "libbinyars.so"
    elif os_name == "Darwin":
        return "libbinyars.dylib"
    else:
        return "Unknown"


PLUGIN_SETTING_DIR = "BinYars Settings.Yara-X Directory.dir"
PLUGIN_SETTING_NAME = "BinYars Settings.BinYars Rust Lib.name"

BINJA_EXTRAS_PLUGIN_SETTINGS: list[tuple[str, dict[str, object]]] = [
    (
        PLUGIN_SETTING_DIR,
        {
            "title": "Set YARA-X Rules Directory",
            "type": "string",
            "default": "",
            "description": "YARA-X rules directory to be used for scanning.",
        },
    ),
    (
        PLUGIN_SETTING_NAME,
        {
            "title": "Set BinYars Rust Binary Name ",
            "type": "string",
            "default": get_os_libbinyars(),
            "description": "The name of the compiled libbinyars file.\nThis file should be in the local plugin dir.",
        },
    ),
]


def register_settings() -> bool:
    settings = Settings()

    for setting_name, setting_properties in BINJA_EXTRAS_PLUGIN_SETTINGS:
        if settings.contains(setting_name):
            logger.log_info(f"Setting already exists: {setting_name}, skipping.")
            continue

        if not settings.register_setting(setting_name, json.dumps(setting_properties)):
            logger.log_error(
                f"Failed to register setting with name {setting_name}, "
                + f"properties {setting_properties}"
            )
            logger.log_error("Abandoning setting registration")
            return False

    return True


if not register_settings():
    logger.log_error("Failed to initialize BinYars Sidebar Widget plugin settings")

#################################################
# Copy the binyars rust library up to the
# root of the plugin folder
#################################################
lib = Path(os.path.join(user_plugin_path(), "binyars-sidewidgit", get_os_libbinyars()))
if lib.exists():
    shutil.move(lib.resolve(), os.path.join(user_plugin_path(), get_os_libbinyars()))
    logger.log_alert(
        "Hi, BinYars here!\n\n"
        "First, Thank You for installing BinYars!\n\n"
        "This is NOT an error; however, we are abusing this log alert feature\n"
        "to let you know that the BinYars rust componenet has been installed\n"
        "(aka. copied to the root of the plugin dir).\n\n"
        "Restart BinaryNinja to load this BinYars rust instance into BinaryNinja.\n\n"
        "Upon restarting BinaryNinja, this mesage should NOT reappear.\n\n"
        "If there is a better way to install the rust component, please create\n"
        "an issue here: https://github.com/xorhex/BinYars/issues\n\n"
        "Happy YARA-X Rule Writing,\n"
        "BinYars"
    )
else:
    logger.log_debug(f"{lib.resolve()} does not exists - nothing to install.")

#################################################
# Binary Ninja BinYars Sidebar Widget
#################################################
Sidebar.addSidebarWidgetType(BinYarsSidebarWidgetType())
