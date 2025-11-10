from PySide6.QtCore import Qt, QRect, QSize, Signal, QEvent
from PySide6.QtGui import (
    QColor,
    QPainter,
    QFont,
    QSyntaxHighlighter,
    QTextCharFormat,
    QPalette,
    QTextCursor,
)
from PySide6.QtWidgets import QWidget, QPlainTextEdit, QTextEdit, QVBoxLayout, QToolTip


class PaletteAwareMixin:
    """Mixin providing helpers to access palette colors and luminance."""

    def _get_widget_with_palette(self):
        """Safely get the first QWidget ancestor that has a palette."""
        # For QSyntaxHighlighter, self.document() exists
        doc = getattr(self, "document", lambda: None)()
        obj = doc.parent() if doc else None

        # Climb until we find a QWidget
        while obj and not isinstance(obj, QWidget):
            obj = getattr(obj, "parent", lambda: None)()
        return obj

    def _getLuminance(self) -> int:
        """Compute the perceived luminance of the background color."""
        widget = self._get_widget_with_palette()
        if widget:
            bg = widget.palette().color(QPalette.Base)
        else:
            bg = QColor("#ffffff")

        # Perceived luminance formula (0 = dark, 255 = light)
        return int(0.299 * bg.red() + 0.587 * bg.green() + 0.114 * bg.blue())


class LineNumberArea(QWidget):
    def __init__(self, editor):
        super().__init__(editor)
        self.codeEditor = editor
        self.setMouseTracking(True)

    def sizeHint(self):
        return QSize(self.codeEditor.lineNumberAreaWidth(), 0)

    def paintEvent(self, event):
        self.codeEditor.lineNumberAreaPaintEvent(event)

    def mousePressEvent(self, event):
        numberWidth, statusWidth = self.codeEditor.lineNumberWidths()
        x = event.position().x()

        if x > numberWidth:  # status column
            y = int(event.position().y())
            block = self.codeEditor.firstVisibleBlock()
            top = int(
                self.codeEditor.blockBoundingGeometry(block)
                .translated(self.codeEditor.contentOffset())
                .top()
            )
            height = int(self.codeEditor.blockBoundingRect(block).height())

            while block.isValid() and top <= y:
                if block.isVisible():
                    bottom = top + height
                    if y < bottom:
                        line = block.blockNumber()
                        if line in self.codeEditor._lineStatuses:
                            linestatus = self.codeEditor._lineStatuses[line]
                            self.codeEditor.statusLightClicked.emit(
                                line + 1, linestatus.message
                            )
                        return
                block = block.next()
                top += height
                height = int(self.codeEditor.blockBoundingRect(block).height())

    def mouseMoveEvent(self, event):
        numberWidth, statusWidth = self.codeEditor.lineNumberWidths()
        x = event.position().x()

        if x > numberWidth:  # hovering in status column
            y = int(event.position().y())
            block = self.codeEditor.firstVisibleBlock()
            top = int(
                self.codeEditor.blockBoundingGeometry(block)
                .translated(self.codeEditor.contentOffset())
                .top()
            )
            height = int(self.codeEditor.blockBoundingRect(block).height())

            while block.isValid() and top <= y:
                if block.isVisible():
                    bottom = top + height
                    if y < bottom:
                        line = block.blockNumber()
                        if line in self.codeEditor._lineStatuses:
                            linestatus = self.codeEditor._lineStatuses[line]
                            if linestatus.message:
                                QToolTip.showText(
                                    event.globalPosition().toPoint(),
                                    f"<b>Line {line + 1}</b><br>{linestatus.message}",
                                    self,
                                )
                                return
                block = block.next()
                top += height
                height = int(self.codeEditor.blockBoundingRect(block).height())

        # if no status or outside column → hide tooltip
        QToolTip.hideText()

    def leaveEvent(self, event):
        QToolTip.hideText()
        super().leaveEvent(event)


class LineStatus:
    def __init__(self, color: QColor, message: str = "", col_num: int = -1):
        if isinstance(color, str):
            color = QColor(color)
        self.color = color
        self.message = message
        self.col_num = col_num


class CodeEditor(QPlainTextEdit, PaletteAwareMixin):
    statusLightClicked = Signal(int, str)  # (line, message)
    INDENT_WIDTH = 2  # spaces per tab

    def __init__(self, parent=None):
        super().__init__(parent)
        self._lineNumberArea = LineNumberArea(self)
        self._lineStatuses: dict[int, LineStatus] = {}  # line → LineStatus instance

        self.blockCountChanged.connect(self.updateLineNumberAreaWidth)
        self.updateRequest.connect(self.updateLineNumberArea)
        self.cursorPositionChanged.connect(self.updateLineNumberAreaHighlight)

        # Fire highlights on cursor movement or content change
        self.cursorPositionChanged.connect(self.updateHighlights)
        self.textChanged.connect(self.updateHighlights)

        self.updateLineNumberAreaWidth(0)
        # nice monospace font
        self.setFont(QFont("Courier", 12))
        self._currentLine = -1  # track highlighted line

        self.textChanged.connect(self._onTextChanged)
        self.textChanged.connect(self.updateHighlights)

    def keyPressEvent(self, event):
        cursor = self.textCursor()
        spaces = " " * self.INDENT_WIDTH

        if event.key() == Qt.Key_Tab and not event.modifiers():
            if cursor.hasSelection():
                # indent selected lines
                start = cursor.selectionStart()
                end = cursor.selectionEnd()
                cursor.beginEditBlock()
                cursor.setPosition(start)
                while cursor.position() <= end:
                    cursor.movePosition(QTextCursor.StartOfLine)
                    cursor.insertText(spaces)
                    if not cursor.movePosition(QTextCursor.Down):
                        break
                    end += self.INDENT_WIDTH
                cursor.endEditBlock()
            else:
                # insert spaces at cursor
                cursor.insertText(spaces)
            return

        elif event.key() == Qt.Key_Backtab:  # Shift+Tab
            if cursor.hasSelection():
                start = cursor.selectionStart()
                end = cursor.selectionEnd()
                cursor.beginEditBlock()
                cursor.setPosition(start)
                while cursor.position() <= end:
                    cursor.movePosition(QTextCursor.StartOfLine)
                    block_text = cursor.block().text()
                    if block_text.startswith(spaces):
                        cursor.setPosition(cursor.position())
                        cursor.setPosition(
                            cursor.position() + self.INDENT_WIDTH,
                            QTextCursor.KeepAnchor,
                        )
                        cursor.removeSelectedText()
                        end -= self.INDENT_WIDTH
                    if not cursor.movePosition(QTextCursor.Down):
                        break
                cursor.endEditBlock()
            else:
                block = cursor.block()
                text = block.text()
                if text.startswith(spaces):
                    cursor.beginEditBlock()
                    cursor.setPosition(block.position())
                    cursor.setPosition(
                        block.position() + self.INDENT_WIDTH, QTextCursor.KeepAnchor
                    )
                    cursor.removeSelectedText()
                    cursor.endEditBlock()
            return

        super().keyPressEvent(event)

    def _applyExtraSelections(self):
        """Apply current line highlight and status light/error highlights."""
        extraSelections: list[QTextEdit.ExtraSelection] = []

        # --- Status lights and optional red text ---
        for line, linestatus in self._lineStatuses.items():
            block = self.document().findBlockByNumber(line)
            if not block.isValid():
                continue

            # Red text / background highlight at specific column
            if linestatus.col_num >= 0:
                col = linestatus.col_num
                block_text = block.text()
                if col < len(block_text):
                    cursor = QTextCursor(block)
                    cursor.setPosition(block.position() + col)
                    cursor.setPosition(
                        block.position() + col + 1, QTextCursor.KeepAnchor
                    )

                    selection = QTextEdit.ExtraSelection()
                    selection.cursor = cursor
                    fmt = QTextCharFormat()
                    fmt.setForeground(QColor("red"))
                    fmt.setBackground(QColor("#ffcccc"))
                    selection.format = fmt
                    extraSelections.append(selection)

        self.setExtraSelections(extraSelections)
        self._lineNumberArea.update()

    def _onTextChanged(self):
        """Clear and recompute unmatched brackets for the entire document."""
        # Remove all previous bracket-related statuses
        to_remove = [
            line
            for line, status in self._lineStatuses.items()
            if status.message.startswith("Unmatched bracket")
        ]
        for line in to_remove:
            del self._lineStatuses[line]

        # Re-highlight brackets for all visible text
        self._highlightBrackets()
        self._applyExtraSelections()

    # --------------------------------------------------------
    # New unified entry point
    # --------------------------------------------------------
    def updateHighlights(self):
        """Re-apply highlights: status lights, unmatched brackets, and cursor bracket matching."""
        extraSelections = []

        # --- Status lights / error selections ---
        extraSelections.extend(self._statusSelections())

        # --- Bracket highlighting under cursor ---
        bracket_info = self._getBracketAtCursor()
        if bracket_info:
            pos, char = bracket_info
            match_pos = self._findMatchingBracketPosition(pos, char)

            fmt = QTextCharFormat()
            if match_pos is not None:
                if self._getLuminance() > 128:
                    fmt.setForeground(QColor("red"))
                else:
                    fmt.setForeground(QColor("yellow"))
                for p in (pos, match_pos):
                    cur = QTextCursor(self.document())
                    cur.setPosition(p)
                    cur.setPosition(p + 1, QTextCursor.KeepAnchor)
                    sel = QTextEdit.ExtraSelection()
                    sel.cursor = cur
                    sel.format = fmt
                    extraSelections.append(sel)
            else:
                # unmatched bracket under cursor
                fmt.setBackground(QColor("#ffcccc"))  # red
                fmt.setForeground(QColor("black"))
                cur = QTextCursor(self.document())
                cur.setPosition(pos)
                cur.setPosition(pos + 1, QTextCursor.KeepAnchor)
                sel = QTextEdit.ExtraSelection()
                sel.cursor = cur
                sel.format = fmt
                extraSelections.append(sel)

        self.setExtraSelections(extraSelections)
        self._lineNumberArea.update()

    def _getBracketAtCursor(self):
        cursor = self.textCursor()
        pos = cursor.position()
        text = self.toPlainText()
        if pos > 0 and text[pos - 1] in "({[)}]":
            return pos - 1, text[pos - 1]
        elif pos < len(text) and text[pos] in "({[)}]":
            return pos, text[pos]
        return None

    def _findMatchingBracketPosition(self, pos, char):
        pairs = {"(": ")", "{": "}", "[": "]", ")": "(", "}": "{", "]": "["}
        match_char = pairs[char]
        direction = 1 if char in "({[" else -1
        depth = 0
        text = self.toPlainText()
        i = pos
        while 0 <= i < len(text):
            c = text[i]
            if c == char:
                depth += 1
            elif c == match_char:
                depth -= 1
                if depth == 0:
                    return i
            i += direction
        return None

    # --------------------------------------------------------
    # Bracket matching logic (pulled out)
    # --------------------------------------------------------
    def _highlightBrackets(self):
        """Scan the document for unmatched brackets and mark them as errors."""
        stack = []
        matches = {"(": ")", "{": "}", "[": "]"}
        selections = []

        for line_num in range(self.blockCount()):
            block = self.document().findBlockByNumber(line_num)
            line = block.text()
            for col_num, char in enumerate(line):
                if char in matches.keys():  # opening
                    stack.append((char, line_num, col_num))
                elif char in matches.values():  # closing
                    if stack and matches[stack[-1][0]] == char:
                        stack.pop()
                    else:
                        # Unmatched closing
                        self.setLineStatus(
                            line_num + 1, "red", "Unmatched bracket", col_num
                        )

        # Any remaining opening brackets are unmatched
        for open_char, line_num, col_num in stack:
            self.setLineStatus(line_num + 1, "red", "Unmatched bracket", col_num)

        return selections  # unused in this refactor

    def _makeBracketSelections(self, doc, pos1, pos2, fmt):
        selections = []
        for p in {pos1, pos2} if pos2 is not None else {pos1}:
            cur = QTextCursor(doc)
            cur.setPosition(p)
            cur.setPosition(p + 1, QTextCursor.KeepAnchor)
            sel = QTextEdit.ExtraSelection()
            sel.cursor = cur
            sel.format = fmt
            selections.append(sel)
        return selections

    def _findMatchingBracket(self, text: str, pos: int, char: str, match_char: str):
        direction = 1 if char in "([{" else -1
        depth = 0
        i = pos
        while 0 <= i < len(text):
            c = text[i]
            if c == char:
                depth += 1
            elif c == match_char:
                depth -= 1
                if depth == 0:
                    return i
            i += direction
        return None

    # --------------------------------------------------------
    # Status selections logic (pulled out from old _applyExtraSelections)
    # --------------------------------------------------------
    def _statusSelections(self):
        selections = []
        doc = self.document()

        for line, linestatus in self._lineStatuses.items():
            block = doc.findBlockByNumber(line)
            if not block.isValid():
                continue
            if linestatus.col_num >= 0:
                col = linestatus.col_num
                block_text = block.text()
                if col < len(block_text):
                    cursor = QTextCursor(block)
                    cursor.setPosition(block.position() + col)
                    cursor.setPosition(
                        block.position() + col + 1, QTextCursor.KeepAnchor
                    )

                    selection = QTextEdit.ExtraSelection()
                    selection.cursor = cursor
                    fmt = QTextCharFormat()
                    fmt.setForeground(QColor("red"))
                    fmt.setBackground(QColor("#ffcccc"))
                    selection.format = fmt
                    selections.append(selection)

        return selections

    def setLineStatus(
        self, line: int, color: QColor | str, message: str = "", col_num: int = -1
    ):
        """Set a status light and optional error text for a 1-based line."""
        self._lineStatuses[line - 1] = LineStatus(color, message, col_num)
        self._applyExtraSelections()
        self._lineNumberArea.update()

    def clearLineStatus(self, line: int):
        idx = line - 1
        if idx in self._lineStatuses:
            del self._lineStatuses[idx]
        self._applyExtraSelections()

    def clearAllLineStatuses(self):
        self._lineStatuses.clear()
        self._applyExtraSelections()

    def lineNumberWidths(self):
        """Return (numberWidth, statusWidth)."""
        digits = len(str(max(1, self.blockCount())))
        numberWidth = 4 + self.fontMetrics().horizontalAdvance("9") * digits
        statusWidth = self.fontMetrics().height()
        return numberWidth, statusWidth

    def lineNumberAreaWidth(self):
        numberWidth, statusWidth = self.lineNumberWidths()
        return numberWidth + statusWidth + 6

    def updateLineNumberAreaHighlight(self):
        """Track cursor line for highlighting."""
        self._currentLine = self.textCursor().blockNumber()
        self._lineNumberArea.update()

    def updateLineNumberAreaWidth(self, _):
        self.setViewportMargins(self.lineNumberAreaWidth(), 0, 0, 0)

    def updateLineNumberArea(self, rect, dy):
        if dy:
            self._lineNumberArea.scroll(0, dy)
        else:
            self._lineNumberArea.update(
                0, rect.y(), self._lineNumberArea.width(), rect.height()
            )

        if rect.contains(self.viewport().rect()):
            self.updateLineNumberAreaWidth(0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self._lineNumberArea.setGeometry(
            QRect(cr.left(), cr.top(), self.lineNumberAreaWidth(), cr.height())
        )

    def lineNumberAreaPaintEvent(self, event):
        painter = QPainter(self._lineNumberArea)

        # Use the widget's background color instead of hard-coded
        gutter_bg = self._lineNumberArea.palette().color(QPalette.Base)
        painter.fillRect(event.rect(), gutter_bg)

        block = self.firstVisibleBlock()
        blockNumber = block.blockNumber()
        top = int(
            self.blockBoundingGeometry(block).translated(self.contentOffset()).top()
        )
        bottom = top + int(self.blockBoundingRect(block).height())
        lineHeight = self.fontMetrics().height()

        numberWidth, statusWidth = self.lineNumberWidths()
        lightX = numberWidth + 2
        radius = lineHeight // 3

        # Highlight color from palette
        highlight_color = self._lineNumberArea.palette().color(QPalette.Highlight)
        highlight_text_color = self._lineNumberArea.palette().color(
            QPalette.HighlightedText
        )

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(blockNumber + 1)

                # highlight current line number
                if blockNumber == self._currentLine:
                    painter.fillRect(0, top, numberWidth, lineHeight, highlight_color)
                    painter.setPen(highlight_text_color)
                else:
                    painter.setPen(self._lineNumberArea.palette().color(QPalette.Text))

                painter.drawText(
                    0, top, numberWidth - 2, lineHeight, Qt.AlignRight, number
                )

                # draw status light if present
                if blockNumber in self._lineStatuses:
                    status = self._lineStatuses[blockNumber]
                    painter.setBrush(status.color)
                    painter.setPen(Qt.NoPen)
                    cx = lightX + radius
                    cy = top + (lineHeight // 2)
                    painter.drawEllipse(
                        cx - radius, cy - radius, radius * 2, radius * 2
                    )

            block = block.next()
            top = bottom
            bottom = top + int(self.blockBoundingRect(block).height())
            blockNumber += 1

    def highlightCurrentLine(self):
        self._applyExtraSelections()


class YaraHighlighter(QSyntaxHighlighter, PaletteAwareMixin):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlightingRules = []

        # --- Keywords ---
        keywordFormat = QTextCharFormat()
        keywordFormat.setForeground(QColor("#2980b9"))  # blue
        keywordFormat.setFontWeight(QFont.Bold)
        keywords = [
            "rule",
            "meta",
            "strings",
            "condition",
            "import",
            "and",
            "or",
            "not",
            "true",
            "false",
            "with",
            "icontains",
            "contains",
            "wide",
            "ascii",
            "all",
            "int8",
            "int16",
            "int32",
            "int8be",
            "int16be",
            "int32be",
            "uint8",
            "uint16",
            "uint32",
            "uint8be",
            "uint16be",
            "uint32be",
            "none",
            "them",
            "endswith",
            "any",
            "xor",
            "entrypoint",
            "iendswith",
            "of",
            "defined",
            "iequals",
            "at",
            "filesize",
            "in",
            "istartswith",
            "private",
            "base64",
            "base64wide",
            "for",
            "include",
            "startswith",
            "global",
            "nocase",
            "fullword",
            "matches",
        ]
        for word in keywords:
            self.highlightingRules.append((rf"\b{word}\b", keywordFormat))

        # --- Identifiers ($variable) ---
        idFormat = QTextCharFormat()
        idFormat.setForeground(QColor("#8e44ad"))  # purple
        self.highlightingRules.append((r"\$[A-Za-z0-9_]+", idFormat))

        # --- Hex blocks { 6A 40 ?? 68 } ---
        hexBlockFormat = QTextCharFormat()
        hexBlockFormat.setForeground(QColor("#27ae60"))  # green too
        self.highlightingRules.append((r"\{[^}]*\}", hexBlockFormat))

        # --- Numeric values (decimals + hex like 0x1A3F) ---
        numberFormat = QTextCharFormat()
        numberFormat.setForeground(QColor("#27ae60"))  # green
        self.highlightingRules.append((r"\b0x[0-9A-Fa-f]+\b", numberFormat))
        self.highlightingRules.append((r"\b\d+\b", numberFormat))

        # --- Strings "..." or '...' ---
        stringFormat = QTextCharFormat()
        # stringFormat.setForeground(QColor("#27ae60"))  # green
        stringFormat.setForeground(QColor("orange"))
        self.highlightingRules.append((r'"[^"\\]*(\\.[^"\\]*)*"', stringFormat))
        self.highlightingRules.append((r"'[^'\\]*(\\.[^'\\]*)*'", stringFormat))

        # --- Single-line comments (// ...) ---
        self.commentFormat = QTextCharFormat()
        self.commentFormat.setFontItalic(True)

        self.highlightingRules.append((r"//[^\n]*", self.commentFormat))

        # --- Multiline comment markers (/* ... */) ---
        self.commentStart = r"/\*"
        self.commentEnd = r"\*/"

        # --- Watch for theme changes (PaletteChange) ---
        if parent is not None:
            parent.installEventFilter(self)

    def eventFilter(self, obj, event):
        """Listen for palette changes and trigger rehighlight."""
        if event.type() == QEvent.PaletteChange:
            self._updateCommentColor()
            self.rehighlight()
        return super().eventFilter(obj, event)

    def _updateCommentColor(self):
        """Set comment color based on current palette background brightness."""
        if self._getLuminance() < 128:
            # Dark background → light gray comments
            color = QColor("yellow")
        else:
            # Light background → darker gray comments
            color = QColor("red")

        self.commentFormat.setForeground(color)

    def highlightBlock(self, text: str):
        import re

        # Dynamically update comment color before applying rules
        self._updateCommentColor()

        # Apply all single-line patterns
        for pattern, fmt in self.highlightingRules:
            for match in re.finditer(pattern, text):
                start, end = match.span()
                self.setFormat(start, end - start, fmt)

        # Handle multiline comments
        self.setCurrentBlockState(0)

        startIndex = 0
        if self.previousBlockState() != 1:
            startIndex = text.find("/*")

        while startIndex >= 0:
            endIndex = text.find("*/", startIndex)
            if endIndex == -1:
                self.setCurrentBlockState(1)
                commentLength = len(text) - startIndex
            else:
                commentLength = endIndex - startIndex + 2
            self.setFormat(startIndex, commentLength, self.commentFormat)
            startIndex = text.find("/*", startIndex + commentLength)


# --- Wrapper widget ---
class CodeEditorWidget(QWidget):
    # re-declare the signal so it exists on this wrapper
    statusLightClicked = Signal(int, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.editor = CodeEditor(self)
        self.highlighter = YaraHighlighter(self.editor.document())
        layout.addWidget(self.editor)
        self.setLayout(layout)

        # forward inner editor's signal to the wrapper
        self.editor.statusLightClicked.connect(self.statusLightClicked)

    def setText(self, text: str):
        self.editor.setPlainText(text)

    def text(self) -> str:
        return self.editor.toPlainText()

    def clear(self):
        self.editor.setPlainText("")
        self.editor.clearAllLineStatuses()

    def setLineStatus(
        self, line: int, color: QColor | str, message: str = "", col_num: int = -1
    ):
        self.editor.setLineStatus(line, color, message, col_num)

    def clearLineStatus(self, line: int):
        self.editor.clearLineStatus(line)

    def clearAllLineStatuses(self):
        self.editor.clearAllLineStatuses()
