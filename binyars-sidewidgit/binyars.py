from binaryninjaui import (
    SidebarWidget,
    SidebarWidgetType,
    UIActionHandler,
    SidebarWidgetLocation,
    SidebarContextSensitivity,
    ViewFrame,
)

from PySide6.QtCore import Qt, QRectF, QSize, Property, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLayout,
    QVBoxLayout,
    QLabel,
    QWidget,
    QFrame,
    QTextEdit,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QListWidgetItem,
    QSizePolicy,
    QListWidget,
    QComboBox,
    QFileDialog,
    QLineEdit,
)
from PySide6.QtGui import (
    QImage,
    QPainter,
    QColor,
    QFontMetrics,
    QPen,
)

from binaryninja.log import Logger
from binaryninja import BinaryView, Settings

import sqlite3
import ast
import json
import threading
import re
from enum import Enum
import os
import platform
from collections import defaultdict

from .binyarscanner import BinYarScanner, Identifier, ConsoleEntry, ConsoleEntryGroup
from .binyarseditor import CodeEditorWidget


logger = Logger(session_id=0, logger_name=__name__)

KEY = "BinYars"
PLUGIN_RULES_SERIALIZED_FILE = "yarax.compiled.bin"
PLUGIN_SETTINGS_DIR = "BinYars Settings.Yara-X Directory.dir"


def get_os_alt():
    os_name = platform.system()
    if os_name == "Windows":
        return "Windows"
    elif os_name == "Linux":
        return "Linux"
    elif os_name == "Darwin":
        return "Mac"
    else:
        return "Unknown"


def get_file_id(bv: BinaryView) -> str:
    # bndb file, get the File ID from the sqlite db
    if bv.file is not None:
        if bv.file.database is not None:
            with sqlite3.connect(bv.file.filename) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT value FROM global WHERE name = 'project_binary_id'"
                )
                row = cursor.fetchone()
            return row[0][4:][1:-1].decode("utf-8") if row else None
        # if file, then just get the File ID
        else:
            return "".join(bv.file.filename.split("/")[-2:])


class Status(Enum):
    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"


class StatusLight(QWidget):
    """A small circular LED-like indicator."""

    statusChanged = Signal(object)

    _COLORS = {
        Status.GREEN: QColor(46, 204, 113),  # green
        Status.YELLOW: QColor(241, 196, 15),  # yellow
        Status.RED: QColor(231, 76, 60),  # red
    }

    def __init__(self, size: int = 14, status: Status = Status.RED, parent=None):
        super().__init__(parent)
        self._diameter = max(8, size)
        self._status = status
        self.setFixedSize(QSize(self._diameter, self._diameter))
        self.setToolTip(self._status.value.capitalize())

    def sizeHint(self) -> QSize:
        return QSize(self._diameter, self._diameter)

    def minimumSizeHint(self) -> QSize:
        return self.sizeHint()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)

        # Circle bounds
        d = min(self.width(), self.height())
        rect = QRectF(1, 1, d - 2, d - 2)

        # Fill with current color (with a slight radial-ish effect)
        color = QColor(self._COLORS[self._status])
        painter.setPen(QPen(Qt.black, 0.8, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))

        # base fill
        painter.setBrush(color)
        painter.drawEllipse(rect)

        # subtle highlight
        highlight = QColor(255, 255, 255, 80)
        painter.setBrush(highlight)
        highlight_rect = QRectF(
            rect.x() + d * 0.15,
            rect.y() + d * 0.15,
            rect.width() * 0.5,
            rect.height() * 0.5,
        )
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(highlight_rect)

    # --- API ---
    def getStatus(self) -> Status:
        return self._status

    def setStatus(self, status: Status | str):
        if isinstance(status, str):
            status = Status(status.lower())
        if status != self._status:
            self._status = status
            self.setToolTip(self._status.value.capitalize())
            self.statusChanged.emit(self._status)
            self.update()

    status = Property(object, fget=getStatus, fset=setStatus, notify=statusChanged)

    # Convenience setters
    def setGreen(self):
        self.setStatus(Status.GREEN)

    def setYellow(self):
        self.setStatus(Status.YELLOW)

    def setRed(self):
        self.setStatus(Status.RED)


class LabeledStatus(QWidget):
    """
    Composite widget: [StatusLight]  [Label text]
    """

    def __init__(
        self,
        text: str = "Status",
        status: Status = Status.RED,
        led_size: int = 14,
        parent=None,
    ):
        super().__init__(parent)

        self._label = QLabel(text, self)
        self._label.setAlignment(
            Qt.AlignLeft | Qt.AlignVCenter
        )  # <-- ensure left aligned
        self._light = StatusLight(size=led_size, status=status, parent=self)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(self._light, 0, Qt.AlignVCenter)
        layout.addWidget(self._label, 1, Qt.AlignVCenter)
        self.setLayout(layout)

        # Keep a sensible minimum height based on font
        fm = QFontMetrics(self._label.font())
        self.setMinimumHeight(max(self._light.sizeHint().height(), fm.height() + 6))

    # --- Label API ---
    def text(self) -> str:
        return self._label.text()

    def setText(self, text: str):
        self._label.setText(text)

    # --- Status API (forwarders) ---
    def status(self) -> Status:
        return self._light.getStatus()

    def setStatus(self, status: Status | str):
        self._light.setStatus(status)

    def setGreen(self):
        self._light.setGreen()

    def setYellow(self):
        self._light.setYellow()

    def setRed(self):
        self._light.setRed()

    def setLabelAndStatus(self, text: str, status: Status | str):
        """
        Convenience function to set both the label text and status color.

        Example:
            widget.setLabelAndStatus("Connected", "green")
        """
        self.setText(text)
        self.setStatus(status)

    # Expose the signal
    @property
    def statusChanged(self) -> Signal:
        return self._light.statusChanged


class ConsoleLogWidget(QWidget):
    def __init__(self, groupby: str, entries: list[ConsoleEntry], parent=None):
        super().__init__(parent)

        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        # Name
        layout.addWidget(QLabel(f"Group: {groupby}"))
        for entry in entries:
            layout.addWidget(QLabel(f"  {entry.child}: {entry.value}"))
        layout.addLayout(layout)

        self.setLayout(layout)

        self.setAutoFillBackground(True)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setStyleSheet("QWidget { background: transparent; }")


class IdentifierWidget(QWidget):
    def __init__(self, identifier: Identifier, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        # Name
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Name:"))
        name_layout.addWidget(QLabel(identifier.name), 1)
        layout.addLayout(name_layout)

        # Offset
        offset_layout = QHBoxLayout()
        offset_layout.addWidget(QLabel("Offset:"))
        offset_layout.addWidget(QLabel(str(identifier.offset)), 1)
        layout.addLayout(offset_layout)

        # Length
        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Length:"))
        length_layout.addWidget(QLabel(str(identifier.length)), 1)
        layout.addLayout(length_layout)

        # Data
        data_layout = QHBoxLayout()
        data_layout.addWidget(QLabel("Data:"))
        data_value = AutoResizingTextEdit()
        data_value.setText(" ".join(f"{x:02X}" for x in identifier.data))
        data_value.setReadOnly(True)
        data_layout.addWidget(data_value, 1)
        layout.addLayout(data_layout)

        self.setLayout(layout)

        self.setAutoFillBackground(True)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setStyleSheet("QWidget { background: transparent; }")


# Sidebar widgets must derive from SidebarWidget, not QWidget.
# SidebarWidget is a QWidget but
# provides callbacks for sidebar events, and must be created with a title.
class BinYarsSidebarWidget(SidebarWidget):
    def __init__(self, name, frame: ViewFrame, data):
        SidebarWidget.__init__(self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        self.bv = None

        self.layout = QVBoxLayout()

        self.tabs = QTabWidget()
        self.hit_details = QScanResultSelectedSection()
        self.hit_section = QScanResultsHitSection(self.hit_details)
        tab1 = QTab([self.hit_section])
        _ = self.tabs.addTab(tab1, "Scan Results")

        self.editor = QScanRuleEditSection()
        tab2 = QTab([self.editor])
        _ = self.tabs.addTab(tab2, "Rule Editor")

        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)

    def notifyViewChanged(self, view_frame):
        logger.log_debug("View changed")
        if view_frame is not None:
            view = view_frame.getCurrentViewInterface()
            self.bv = view.getData()
            logger.log_debug(f"View changed to: {self.bv.file.view}")
            self.hit_section.get_data(self.bv)
            self.hit_details.update_bv(self.bv)
            self.editor.update_bv(self.bv)
        else:
            self.bv = None


class QTab(QWidget):
    def __init__(self, widgets: list[QWidget], addLineBetweenEach=True):
        super(QTab, self).__init__()

        self.layout = QVBoxLayout()
        self.layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        for widget in widgets:
            if isinstance(widget, QScanResultsHitSection):
                self.layout.addWidget(widget, 1)
            elif isinstance(widget, QScanRuleEditSection):
                self.layout.addWidget(widget, 1)
            else:
                self.layout.addWidget(widget)
            if addLineBetweenEach:
                self.layout.addWidget(QHLine())
        self.layout.addStretch()
        self.setLayout(self.layout)


class QTitle(QLabel):
    def __init__(self, title: str):
        super(QTitle, self).__init__(title)
        font = self.font()
        font.setBold(True)
        self.setFont(font)


class QHLine(QFrame):
    def __init__(self):
        super(QHLine, self).__init__()
        self.setFrameShape(QFrame.HLine)
        self.setFrameShadow(QFrame.Sunken)


class AutoResizingTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super(AutoResizingTextEdit, self).__init__(parent)

        # This seems to have no effect.
        # I have expected that it will cause self.hasHeightForWidth()
        # to start returning True, but it hasn't - that's why I hardcoded
        # it to True there anyway.
        # I still set it to True in size policy just in case - for consistency.
        size_policy = self.sizePolicy()
        size_policy.setHeightForWidth(True)
        size_policy.setVerticalPolicy(QSizePolicy.Preferred)
        self.setSizePolicy(size_policy)

        self.textChanged.connect(lambda: self.updateGeometry())

    def setMinimumLines(self, num_lines):
        """Sets minimum widget height to a value
        corresponding to specified number of lines
        in the default font."""

        self.setMinimumSize(
            self.minimumSize().width(), self.lineCountToWidgetHeight(num_lines)
        )

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        margins = self.contentsMargins()

        if width >= margins.left() + margins.right():
            document_width = width - margins.left() - margins.right()
        else:
            # If specified width can't even fit the margin,
            # there's no space left for the document
            document_width = 0

        # Cloning the whole document only to check its size at
        # different width seems wasteful
        # but apparently it's the only and preferred way to do
        # this in Qt >= 4. QTextDocument does not
        # provide any means to get height for specified width
        # (as some QWidget subclasses do).
        # Neither does QTextEdit. In Qt3 Q3TextEdit had working
        # implementation of heightForWidth()
        # but it was allegedly just a hack and was removed.
        #
        # The performance probably won't be a problem here
        # because the application is meant to
        # work with a lot of small notes rather than few
        # big ones. And there's usually only one
        # editor that needs to be dynamically resized - the one having focus.
        document = self.document().clone()
        document.setTextWidth(document_width)

        return margins.top() + document.size().height() + margins.bottom()

    def sizeHint(self):
        original_hint = super(AutoResizingTextEdit, self).sizeHint()
        return QSize(original_hint.width(), self.heightForWidth(original_hint.width()))

    def lineCountToWidgetHeight(self, num_lines):
        """Returns the number of pixels corresponding to the height
        of specified number of lines
        in the default font."""

        # ASSUMPTION: The document uses only the default font

        assert num_lines >= 0

        widget_margins = self.contentsMargins()
        document_margin = self.document().documentMargin()
        font_metrics = QFontMetrics(self.document().defaultFont())

        # font_metrics.lineSpacing() is ignored because it
        # seems to be already included in font_metrics.height()
        return (
            widget_margins.top()
            + document_margin
            + max(num_lines, 1) * font_metrics.height()
            + self.document().documentMargin()
            + widget_margins.bottom()
        )

        # return QSize(original_hint.width(), minimum_height_hint)


class ScanResults:
    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.file_id = get_file_id(self.bv)

    def get_scan_results(self) -> list[str]:
        logger.log_debug(f"Getting scan results for {self.file_id}")
        results = []
        if self.bv.project is not None:
            logger.log_debug(f"Getting project scan results for {self.file_id}")
            try:
                metadata = json.loads(self.bv.project.query_metadata(KEY))
                key = list(filter(lambda x: x == self.file_id, metadata))
                if len(key) > 0:
                    results.extend(metadata[key[0]])
            except KeyError:
                pass
        if self.bv.file.database is not None:
            if KEY in self.bv.metadata.keys():
                logger.log_debug(f"Getting file scan results for {self.file_id}")
                pjson: list = json.loads(self.bv.query_metadata(KEY))
                for item in pjson:
                    if item["rule"] not in [r["rule"] for r in results]:
                        results.append(item)
                    else:
                        logger.log_info(
                            f"Rule `{item['rule']}` also found at the project level, so skipping adding it again at the file level."
                        )
                # results.extend(json.loads(self.bv.query_metadata(KEY)))
        logger.log_debug(f"Rules found {results}")
        return results


class ClickableTextEdit(QLineEdit):  # assumes AutoResizingTextEdit inherits QTextEdit
    clicked = Signal()

    def mousePressEvent(self, event):
        self.clicked.emit()  # emit signal when clicked
        super().mousePressEvent(event)


class FilePicker(QWidget):
    fileSelected = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        # Label
        self.label = QLabel("File Name:")
        layout.addWidget(self.label)

        # Clickable text edit
        self.text_edit = ClickableTextEdit()
        self.text_edit.setReadOnly(True)  # prevent manual typing
        layout.addWidget(self.text_edit)

        self.setLayout(layout)

        # Connect click signal to dialog
        self.text_edit.clicked.connect(self.open_file_dialog)

    def open_file_dialog(self):
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Select File",
            Settings().get_string(PLUGIN_SETTINGS_DIR),
            "All Files (*);;Yara Files (*.yar)",
        )
        if file_name:
            self.text_edit.setText(file_name)
            self.fileSelected.emit(file_name)

    def file_path(self) -> str:
        """Convenience getter for the selected file path."""
        return self.text_edit.text()

    def clear(self):
        self.text_edit.setText("")


class EditorActions(QWidget):
    newFileRequested = Signal()
    fileSaveRequested = Signal(str)  # Save (may reuse last file)
    fileSaveAsRequested = Signal(str)  # Save As (always dialog)
    scanRequested = Signal()
    formatRequested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)

        self._last_saved_path: str | None = None

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # Buttons
        self.new_btn = QPushButton("New")
        self.save_btn = QPushButton("Save")
        self.save_as_btn = QPushButton("Save As")
        self.scan_btn = QPushButton("Scan")
        self.format_btn = QPushButton("Format")

        # Add to layout
        layout.addWidget(self.new_btn)
        layout.addWidget(self.save_btn)
        layout.addWidget(self.save_as_btn)
        layout.addWidget(self.scan_btn)
        layout.addWidget(self.format_btn)

        self.setLayout(layout)

        # Connect buttons
        self.new_btn.clicked.connect(self.newFileRequested.emit)
        self.save_btn.clicked.connect(self.save_file)
        self.save_as_btn.clicked.connect(self.save_file_as)
        self.scan_btn.clicked.connect(self.scanRequested.emit)
        self.format_btn.clicked.connect(self.formatRequested.emit)

    def save_file(self, path: str | None = None):
        """Save to the provided path, the file picker path, or the last used path."""
        if path:
            self._last_saved_path = path
            self.fileSaveRequested.emit(path)
            return

        # no explicit path: check last path
        if self._last_saved_path:
            self.fileSaveRequested.emit(self._last_saved_path)
        else:
            self.save_file_as()

    def save_file_as(self, initial_path: str | None = None) -> str | None:
        """Always open a file dialog and emit the chosen path. Returns the chosen file or None."""
        start_path = initial_path or Settings().get_string(PLUGIN_SETTINGS_DIR)

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save File As",
            start_path,
            "All Files (*);;Yara Files (*.yar)",
        )
        if file_path:
            self._last_saved_path = file_path
            self.fileSaveAsRequested.emit(file_path)
            return file_path
        return None


class QScanRuleEditSection(QWidget):
    def __init__(self):
        super(QScanRuleEditSection, self).__init__()
        self.layout = QVBoxLayout()

        self.file_picker = FilePicker(self)
        self.layout.addWidget(self.file_picker, 0)

        self.editor = CodeEditorWidget()
        self.editor.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.layout.addWidget(self.editor, 1)

        self.status = LabeledStatus("", Status.YELLOW)
        self.layout.addWidget(self.status, 0)

        self.actions = EditorActions(self)
        self.layout.addWidget(self.actions, 0)

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setLayout(self.layout)

        # Connect actions
        self.actions.newFileRequested.connect(self.new_rule_file)
        self.actions.fileSaveRequested.connect(self.save_to_file)
        self.actions.fileSaveAsRequested.connect(self._save_as_and_update_picker)
        self.actions.scanRequested.connect(self.run_scan)
        self.actions.formatRequested.connect(self.format_text)
        self.file_picker.fileSelected.connect(self.load_file)
        self.editor.statusLightClicked.connect(self.show_error)

        self.bv = None

    def update_bv(self, bv):
        self.bv = bv

    # Connect click signal
    def show_error(self, line, message):
        logger.log_debug(f"Clicked status at line {line}: {message}")

    def _save_as_and_update_picker(self, new_path):
        new_path = self.save_to_file(new_path)
        if new_path:
            self.file_picker.text_edit.setText(new_path)

    def load_file(self):
        success = False
        path = self.file_picker.file_path()
        try:
            with open(path, "r") as f:
                self.editor.setText(f.read())
            success = True
            self.actions._last_saved_path = path
            self.status.setLabelAndStatus("Rule File Loaded", Status.GREEN)
        except Exception as ex:
            if success:
                self.status.setLabelAndStatus("Rule File Loaded", Status.GREEN)
            else:
                self.status.setLabelAndStatus(
                    "Error Loading File - Is it a Yara-X text file?", Status.RED
                )
            logger.log_debug(f"Error occurred while loading rule file {path} : {ex}")

    def new_rule_file(self):
        self.editor.clear()
        self.file_picker.clear()
        self.actions._last_saved_path = None  # reset last saved file
        self.status.setLabelAndStatus("", Status.YELLOW)

    def run_scan(self):
        scanner = BinYarScanner()
        self.editor.clearAllLineStatuses()
        if error_msg := scanner.rule_compiles(self.editor.text()):
            # Add statuses with messages
            line_no, error_no, msg, col_num = parse_yarax_error(error_msg)
            self.status.setLabelAndStatus(f"Compile error: {error_no}", Status.RED)
            self.editor.setLineStatus(line_no, "red", msg, col_num)
        else:
            if self.bv:

                def worker():
                    results_json = scanner.scan_rule_against_bytes(
                        self.bv.file.raw.read(0, self.bv.file.raw.length),
                        self.editor.text(),
                    )
                    count = len(results_json)
                    if count == 0:
                        self.status.setLabelAndStatus("No Rules Matched", Status.RED)
                    else:
                        word = "Rule" if count == 1 else "Rules"
                        self.status.setLabelAndStatus(
                            f"{count} {word} Matched", Status.GREEN
                        )

                    logger.log_debug(
                        f"Test scan against current file returned: {results_json}"
                    )

                thread = WorkerHeartbeatThread(worker)
                thread.start()

    def format_text(self):
        """Placeholder for format action."""
        scanner = BinYarScanner()
        self.editor.clearAllLineStatuses()
        if error_msg := scanner.rule_compiles(self.editor.text()):
            # Add statuses with messages
            line_no, error_no, msg, col_num = parse_yarax_error(error_msg)
            self.status.setLabelAndStatus(f"Compile error: {error_no}", Status.RED)
            self.editor.setLineStatus(line_no, "red", msg, col_num)
        else:
            if fmt_rule := scanner.rule_fmt(self.editor.text()):
                if self.editor.text() == fmt_rule:
                    self.status.setLabelAndStatus("No Change", Status.YELLOW)
                else:
                    self.editor.setText(fmt_rule)
                    self.status.setLabelAndStatus("Reformatted Rule", Status.GREEN)

    def save_to_file(self, path: str | None = None):
        scanner = BinYarScanner()
        self.editor.clearAllLineStatuses()
        if error_msg := scanner.rule_compiles(self.editor.text()):
            # Add statuses with messages
            line_no, error_no, msg, col_num = parse_yarax_error(error_msg)
            self.status.setLabelAndStatus(f"Compile error: {error_no}", Status.RED)
            self.editor.setLineStatus(line_no, "red", msg, col_num)
        else:
            """Write editor contents to a file. If no path given, use file picker path."""
            if not path:
                path = self.file_picker.file_path()
            if not path:
                logger.log_error("No file selected for Save")
                return

            if len(self.editor.text()) > 0:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.editor.text())
                self.status.setLabelAndStatus(f"Saved to {path}", Status.GREEN)
            else:
                self.status.setLabelAndStatus("You forgot to write a rule", Status.RED)
            return path


def parse_yarax_error(msg: str) -> (int, str, str, int):
    """
    Parses a YARA compiler error message and returns:
      - line number (1-based)
      - error code (like E001)
      - detailed message after the caret (^)
      - the column of in the line the error starts
    """
    # Extract the error code inside square brackets: [E001]
    code_match = re.search(r"error\[(E\d+)\]:\s+(.*)", msg)
    error_code = code_match.group(1) if code_match else "Unknown"
    error_text = code_match.group(2) if code_match else "Unknown"
    logger.log_debug(error_text)

    # Extract the line number (from --> line:X:Y)
    line_match = re.search(r"--> line:(\d+):(\d+)", msg)
    line_number = int(line_match.group(1)) if line_match else -1
    column_number = int(line_match.group(2)) if line_match else -1

    # Extract the message after the caret
    message = ""
    for line in msg.split("\n"):
        if caret_match := re.search(r"^[^\|]*\|[^\^]*\^\S*(.*)$", line):
            if len(message) == 0:
                message = caret_match.group(1).strip() if caret_match else ""

    return line_number, f"{error_code} -->  {error_text}", message, column_number - 1


class QScanResultSelectedSection(QWidget):
    def __init__(self):
        super(QScanResultSelectedSection, self).__init__()
        self.layout = QVBoxLayout()
        desc_header = QLabel("Description", self)
        self.layout.addWidget(desc_header, 0)
        self.desc_label = AutoResizingTextEdit(self)
        self.desc_label.setReadOnly(True)
        self.desc_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.desc_label.setMaximumHeight(100)
        self.layout.addWidget(self.desc_label, 0)

        self.master_list_widget = QListWidget()
        self.master_list_widget.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Expanding
        )
        self.layout.addWidget(self.master_list_widget, 1)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setLayout(self.layout)

        self.master_list_widget.itemClicked.connect(self.on_item_selected)
        self.bv = None

    def update(
        self,
        rule_desc: str,
        identifiers: list[Identifier],
        console_groups: list[ConsoleEntryGroup],
    ):
        self.desc_label.setText(rule_desc)
        self.master_list_widget.clear()
        # Add ConsoleEntry widgets
        logger.log_debug(f"Console Groups: {console_groups}")
        # Add each console entry group
        for idx, group in enumerate(console_groups):
            item = QListWidgetItem(self.master_list_widget)
            widget = ConsoleLogWidget(
                groupby=group.group,
                entries=group.entries,
                parent=self.master_list_widget,
            )
            item.setSizeHint(widget.sizeHint())
            item.setData(Qt.UserRole, group)  # Store original entries if needed
            self.master_list_widget.addItem(item)
            self.master_list_widget.setItemWidget(item, widget)

            # Add separator unless last group
            if idx < len(console_groups) - 1:
                self.add_separator()

        if len(identifiers) > 0:
            self.add_separator()

        logger.log_debug(f"Identifiers {identifiers}")
        for idx, identifier in enumerate(identifiers):
            item = QListWidgetItem(self.master_list_widget)
            widget = IdentifierWidget(identifier, self.master_list_widget)

            # Set custom widget for the item
            item.setSizeHint(widget.sizeHint())
            item.setData(Qt.UserRole, identifier)
            self.master_list_widget.addItem(item)
            self.master_list_widget.setItemWidget(item, widget)

            if idx < len(identifiers) - 1:
                self.add_separator()

    def update_bv(self, bv: BinaryView):
        self.bv = bv

    def on_item_selected(self, item: QListWidgetItem):
        data = item.data(Qt.UserRole)

        # Handle Identifier
        if isinstance(data, Identifier):
            identifier = data
            logger.log_debug(
                f"Selected Identifier: {identifier.name}, offset={identifier.offset}"
            )
            if self.bv is not None:
                addr = self.bv.get_address_for_data_offset(identifier.offset)
                if addr is not None:
                    addr = int(addr)
                    logger.log_debug(f"offset: {hex(addr)}")
                    logger.log_debug(f"view: {self.bv.file.view}")
                    self.bv.file.navigate(self.bv.file.view, addr)
                else:
                    logger.log_error(f"Offset {hex(identifier.offset)} not found.")

        # Handle ConsoleEntryGroup
        elif isinstance(data, ConsoleEntryGroup):
            console_group = data
            offset_value = console_group.get_offset()
            if offset_value is not None and self.bv is not None:
                logger.log_debug(f"Found offset field with value {offset_value}")
                addr = self.bv.get_address_for_data_offset(offset_value)
                if addr is not None:
                    addr = int(addr)
                    logger.log_debug(f"offset: {hex(addr)}")
                    logger.log_debug(f"view: {self.bv.file.view}")
                    self.bv.file.navigate(self.bv.file.view, addr)
                else:
                    logger.log_error(f"Offset {hex(offset_value)} not found.")

    def clear(self):
        self.desc_label.setText("")
        self.master_list_widget.clear()

    def add_separator(self):
        sep_item = QListWidgetItem(self.master_list_widget)
        sep_line = QFrame(self.master_list_widget)
        sep_line.setFrameShape(QFrame.HLine)
        sep_line.setFrameShadow(QFrame.Sunken)
        sep_item.setSizeHint(sep_line.sizeHint())
        self.master_list_widget.addItem(sep_item)
        self.master_list_widget.setItemWidget(sep_item, sep_line)


class QScanResultsHitSection(QWidget):
    def __init__(self, details: QScanResultSelectedSection):
        super(QScanResultsHitSection, self).__init__()
        self.details = details
        self.layout = QVBoxLayout()

        self.selection_layout = QHBoxLayout()
        self.label = QLabel("YaraX Hits")
        self.selection_layout.addWidget(self.label)
        self.hit_dropdown = QComboBox(self)
        setattr(
            self.hit_dropdown,
            "allItems",
            lambda: [
                self.hit_dropdown.itemText(i) for i in range(self.hit_dropdown.count())
            ],
        )
        self.hit_dropdown.currentIndexChanged.connect(self.hit_index_changed)
        self.selection_layout.addWidget(self.hit_dropdown, 1)
        self.button_reload = QPushButton("Reload", self)
        self.button_reload.clicked.connect(self.reload_action)
        self.selection_layout.addWidget(self.button_reload)
        self.button_rescan = QPushButton("Rescan", self)
        self.button_rescan.clicked.connect(self.rescan_action)
        self.selection_layout.addWidget(self.button_rescan)

        self.selection_widget = QWidget(self)
        self.selection_widget.setLayout(self.selection_layout)
        self.layout.addWidget(self.selection_widget)

        self.layout.addWidget(details, 1)

        self.setLayout(self.layout)
        self.data = None
        self.bv = None

    def get_data(self, bv: BinaryView, force: bool = False):
        self.bv = bv
        self.data = ScanResults(bv).get_scan_results()
        items = [x["rule"] for x in self.data]
        current_items = self.hit_dropdown.allItems()
        if set(items) != set(current_items) or force:
            logger.log_debug(f"Updating dropdown rule list: {items}")
            self.hit_dropdown.clear()
            self.details.clear()
            self.hit_dropdown.addItems(items)

    def select_item_in_hit_dropdown(self, hdropdown: QComboBox, rule_name: str):
        idx: int = hdropdown.findText(rule_name)
        hdropdown.setCurrentIndex(idx)

    def hit_index_changed(self, idx: int):
        logger.log_debug(
            f"Hit index changed {idx}. Lookup up rule "
            f'"{self.hit_dropdown.currentText()}"'
        )
        if self.data is not None:
            rules = list(
                filter(
                    lambda x: x["rule"] == self.hit_dropdown.currentText(), self.data
                )
            )
            if len(rules) == 1:
                rule = rules[0]
                logger.log_debug(f"Loading rule {rule}")
                identifiers: list[Identifier] = []
                for iden in rule["identifiers"]:
                    if isinstance(iden["data"], str):
                        iden_data = ast.literal_eval(iden["data"])
                    else:
                        iden_data = iden["data"]
                    identifiers.append(
                        Identifier(
                            iden["identifier"],
                            iden["offset"],
                            iden["length"],
                            iden_data,
                        )
                    )
                # Step 1: Create ConsoleEntry objects
                console_entries: list[ConsoleEntry] = []
                for entry in rule["console"]:
                    for key, value in entry.items():
                        console_entries.append(ConsoleEntry(key, value))

                # Step 2: Group entries by parent field
                grouped_dict = defaultdict(list)
                for entry in console_entries:
                    grouped_dict[entry.parent].append(entry)

                # Step 3: Create ConsoleEntryGroup objects
                console_groups: list[ConsoleEntryGroup] = [
                    ConsoleEntryGroup(group, entries)
                    for group, entries in grouped_dict.items()
                ]
                self.details.update(rule["desc"], identifiers, console_groups)

    def reload_action(self):
        logger.log_debug("Reload clicked")
        if self.bv is not None:
            self.get_data(self.bv, True)

    def rescan_action(self):
        logger.log_debug("ReScan clicked")

        def worker():
            scanner = BinYarScanner()
            if hits := scanner.scan(self.bv.file.raw.read(0, self.bv.file.raw.length)):
                logger.log_debug(f"Saving hits: {hits}")
                scanner.save(self.bv, hits)
            else:
                logger.log_debug("No hits to save")

        thread = WorkerHeartbeatThread(worker)
        thread.start()


class WorkerHeartbeatThread(threading.Thread):
    def __init__(self, func):
        threading.Thread.__init__(self)
        self.func = func
        self.daemon = True

    def run(self):
        self.func()


def clearLayoutHelper(layout: QLayout):
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget:
            widget.deleteLater()
        else:
            clearLayoutHelper(item.layout())


def wrapWidgetInScrollArea(w: QWidget) -> QWidget:
    pane = QWidget()
    paneLayout = QVBoxLayout()
    paneLayout.setAlignment(Qt.AlignmentFlag.AlignTop)
    paneLayout.addWidget(w)
    pane.setLayout(paneLayout)
    scrollarea = QScrollArea()
    scrollarea.setWidgetResizable(True)
    scrollarea.setWidget(pane, 1)
    return scrollarea


class BinYarsSidebarWidgetType(SidebarWidgetType):
    def __init__(self):
        # Sidebar icons are 28x28 points. Should be at least 56x56 pixels for
        # HiDPI display compatibility. They will be automatically made theme
        # aware, so you need only provide a grayscale image, where white is
        # the color of the shape.
        script_directory = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(script_directory, "binyars.png")
        if os.path.exists(icon_path):
            icon = QImage(icon_path)
        else:
            logger.log_error(f"Icon file {icon_path} not found for binyars")
            return

        # If needed, force resize to 56x56
        if icon.size() != (56, 56):
            icon = icon.scaled(56, 56, Qt.KeepAspectRatio, Qt.SmoothTransformation)

        SidebarWidgetType.__init__(self, icon, "BinYars")

    def createWidget(self, frame, data):
        # This callback is called when a widget needs to be created
        # for a given context. Different
        # widgets are created for each unique BinaryView. They are
        # created on demand when the sidebar
        # widget is visible and the BinaryView becomes active.
        return BinYarsSidebarWidget("BinYars", frame, data)

    def defaultLocation(self):
        # Default location in the sidebar where this widget will appear
        return SidebarWidgetLocation.RightContent

    def contextSensitivity(self):
        # Context sensitivity controls which contexts have separate
        # instances of the sidebar widget.
        # Using `contextSensitivity` instead of the deprecated
        # `viewSensitive` callback allows sidebar
        # widget implementations to reduce resource usage.

        # This example widget uses a single instance and detects view changes.
        return SidebarContextSensitivity.PerViewTypeSidebarContext
