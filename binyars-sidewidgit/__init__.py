from .binyars import BinYarsSidebarWidgetType
from binaryninjaui import Sidebar
from binaryninja import Settings, Logger
import json
import platform

logger = Logger(session_id=0, logger_name=__name__)


def get_os_libbinyars():
    os_name = platform.system()
    if os_name == "Windows":
        return "libbinyars.dll"
    elif os_name == "Linux":
        return "libbinyars.so"
    elif os_name == "Darwin":
        return "libbinhars.dylib"
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
# Basic Emulation Using Unicorn in a sidebar
#################################################
Sidebar.addSidebarWidgetType(BinYarsSidebarWidgetType())
