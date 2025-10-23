from PySide6.QtCore import Qt

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QWidget,
    QPushButton,
    QSizePolicy,
    QStyle,
    QSpacerItem,
    QMessageBox,
)

from binaryninja.log import Logger
from .binyarscanner import BinYarScanner
from .logo import BINYARS_LOGO_BASE64
from .constants import PLUGIN_SETTINGS_DIR

logger = Logger(session_id=0, logger_name=__name__)


class YaraRulesDirWidget(QWidget):
    def __init__(self, current_yara_rules_dir: str | None, parent=None):
        super().__init__(parent)

        scanner = BinYarScanner()
        self.yara_info = scanner.get_yara_version()
        # Horizontal layout
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)

        # QLabel Field Name
        self.yara_rules_label = QLabel("YARA-X Rules Directory: ")
        layout.addWidget(self.yara_rules_label)

        # QLabel For Value
        self.yara_rules_dir = QLabel()
        if current_yara_rules_dir:
            self.update_label(current_yara_rules_dir)
        else:
            self.update_label(f"NEEDS TO BE SET IN THE CONFIG: {PLUGIN_SETTINGS_DIR}")
        layout.addWidget(self.yara_rules_dir)

        # Horizontal spacer to push the button to the right
        spacer = QSpacerItem(
            40,
            20,
            QSizePolicy.Policy.Expanding,  # width expands
            QSizePolicy.Policy.Minimum,  # height stays minimal
        )
        layout.addItem(spacer)

        # Refresh QPushButton
        self.refresh_button = QPushButton("Refresh")
        layout.addWidget(self.refresh_button)

        # Info button
        self.info_button = QPushButton()
        self.info_button.setIcon(
            self.style().standardIcon(QStyle.StandardPixmap.SP_MessageBoxInformation)
        )
        self.info_button.setToolTip("About BinYars")
        layout.addWidget(self.info_button)

        # Connect info button to popup
        self.info_button.clicked.connect(self.show_info_popup)

    def update_label(self, text: str):
        """Helper method to update the QLabel text."""
        self.yara_rules_dir.setText(text)

    def show_info_popup(self):
        """Show a rich-text popup with information about BinYars."""
        logo_data_uri = f"data:image/png;base64,{BINYARS_LOGO_BASE64.strip()}"
        info_text = f"""
        <html>
        <head>
            <style>
                body {{font - family: 'Segoe UI', sans-serif; }}
                h2 {{color: #2b6cb0; margin-bottom: 6px; }}
                p {{margin - top: 4px; margin-bottom: 8px; }}
                ul {{margin - left: 15px; }}
            </style>
        </head>
        <body>
            <table>
                <tr>
                    <td><img src='{logo_data_uri}' width='32' height='32'></td>
                    <td><h2>BinYars</h2></td>
                </tr>
            </table>

            <p><b>BinYars</b> is built leveraging <b>Binary Ninja</b> and <b>YARA-X</b>
            to enable powerful binary pattern analysis and rule-driven workflows.</p>

            <p><b>Developed By: </b><a href='https://blog.xorhex.com'>xorhex</a><p>

            <p>A big THANK YOU to all of the initial testers helping to ensure a quality product out the door!</p>
            <ul>
                <li><a href='https://cxiao.net/'>cxiao</a></li>
            </ul>

            <p>Check for updates and learn more at:<br>
            <a href='https://github.com/xorhex/BinYars'>https://github.com/xorhex/BinYars</a></p>

            <p>Compiled with <a href='https://virustotal.github.io/yara-x/'>YARA-X</a> version: {self.yara_info["yara-x"]}</p>

            <p style='margin-top:12px; font-size: small; color: #666;'>
            © 2025 xorhex. MIT License
            </p>
        </body>
        </html>
        """

        msg = QMessageBox(self)
        msg.setWindowTitle("About BinYars")
        msg.setTextFormat(Qt.TextFormat.RichText)
        msg.setText(info_text)
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.exec()
