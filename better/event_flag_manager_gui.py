import sys
import os
import json
import traceback
from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal, QObject
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QFormLayout,
    QLabel,
    QComboBox,
    QPushButton,
    QTabWidget,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QFileDialog,
    QMessageBox,
    QGroupBox,
    QRadioButton,
    QButtonGroup,
    QSplitter,
    QAbstractItemView,
    QToolButton,
)

try:
    import frida
except ImportError:
    frida = None

try:
    import psutil
except ImportError:
    psutil = None



# Set the working directory
working_directory = os.path.dirname(os.path.abspath(__file__))
os.chdir(working_directory)

DEFAULT_EXCLUDE_FLAGS = [
    0x7EE,
    0x989F30,
    0x3B9ACDE8,
    0x98A10C,
    0x3B9ACDEA,
    0x3B9ACDEB,
]

DEFAULT_PROCESS_NAMES = ["start_protected_game.exe", "nightreign.exe"]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def parse_int_auto(text):
    """Parse a user-provided id string as hex or decimal, same rules as
    the original script (0x prefix, hex letters present, else decimal)."""
    text = text.strip()
    if not text:
        raise ValueError("empty value")
    lowered = text.lower()
    if lowered.startswith("0x"):
        return int(text, 16)
    if any(c in "abcdefABCDEF" for c in text):
        return int(text, 16)
    return int(text, 10)


def load_flags(filename):
    """Yield (flag_id:int, name:str) pairs from an 'id;name' per-line file."""
    flags = []
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ";" not in line:
                continue
            flag_id_str, name = line.split(";", 1)
            flag_id_str = flag_id_str.strip()
            name = name.strip()
            try:
                flag_id = parse_int_auto(flag_id_str)
            except ValueError:
                continue
            flags.append((flag_id, name))
    return flags


def timestamp():
    return datetime.now().strftime("%H:%M:%S")


# --------------------------------------------------------------------------
# Top bar - process selection
# --------------------------------------------------------------------------

class ProcessBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        layout.addWidget(QLabel("Target process:"))

        self.process_combo = QComboBox()
        self.process_combo.setEditable(True)
        self.process_combo.setMinimumWidth(260)
        self.process_combo.addItems(DEFAULT_PROCESS_NAMES)
        self.process_combo.setCurrentIndex(0)
        layout.addWidget(self.process_combo, 1)

        self.refresh_btn = QPushButton("Refresh running processes")
        self.refresh_btn.clicked.connect(self.refresh_processes)
        layout.addWidget(self.refresh_btn)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: gray;")
        layout.addWidget(self.status_label)

        layout.addStretch(1)

        if psutil is None:
            self.status_label.setText("psutil not installed - manual entry only")

    def refresh_processes(self):
        if psutil is None:
            QMessageBox.warning(
                self, "psutil not available",
                "Install psutil to list running processes:\n\n    pip install psutil"
            )
            return

        current_text = self.process_combo.currentText()
        names = set()
        for proc in psutil.process_iter(["name"]):
            name = proc.info.get("name")
            if name:
                names.add(name)

        self.process_combo.clear()
        self.process_combo.addItems(DEFAULT_PROCESS_NAMES)
        for name in sorted(names, key=str.lower):
            if name not in DEFAULT_PROCESS_NAMES:
                self.process_combo.addItem(name)

        idx = self.process_combo.findText(current_text)
        if idx >= 0:
            self.process_combo.setCurrentIndex(idx)
        else:
            self.process_combo.setCurrentText(current_text)

        self.status_label.setText(f"{len(names)} running processes found")

    def process_name(self):
        return self.process_combo.currentText().strip()


# --------------------------------------------------------------------------
# Trigger tab
# --------------------------------------------------------------------------

class TriggerWorker(QThread):
    finished_ok = Signal(str)
    finished_err = Signal(str)

    def __init__(self, process_name, script_path, flag_id, lock_state, parent=None):
        super().__init__(parent)
        self.process_name = process_name
        self.script_path = script_path
        self.flag_id = flag_id
        self.lock_state = lock_state

    def run(self):
        if frida is None:
            self.finished_err.emit("The 'frida' package is not installed.")
            return
        try:
            session = frida.attach(self.process_name)
        except frida.ProcessNotFoundError:
            self.finished_err.emit(
                f"Process '{self.process_name}' not found. Ensure the game is running."
            )
            return
        except Exception as exc:
            self.finished_err.emit(f"Attach failed: {exc}")
            return

        try:
            with open(self.script_path, "r", encoding="utf-8") as f:
                script_code = f.read()
        except OSError as exc:
            session.detach()
            self.finished_err.emit(f"Could not read script file: {exc}")
            return

        script_code = script_code.replace("{{PROCESS_NAME}}", self.process_name)

        try:
            script = session.create_script(script_code)
            script.load()
            api = script.exports_sync
            response = api.set_flag(self.flag_id, self.lock_state)
        except Exception as exc:
            session.detach()
            self.finished_err.emit(f"Execution error: {exc}\n{traceback.format_exc()}")
            return

        session.detach()

        if response.get("success"):
            self.finished_ok.emit(
                f"Success! Native Return Code: {response.get('result')}"
            )
        else:
            self.finished_err.emit(
                f"Execution aborted: {response.get('reason')}"
            )


class TriggerTab(QWidget):
    def __init__(self, process_bar, parent=None):
        super().__init__(parent)
        self.process_bar = process_bar
        self.worker = None

        root = QVBoxLayout(self)

        # --- file selection row ---
        file_row = QHBoxLayout()
        file_row.addWidget(QLabel("Flags file:"))
        self.flags_path_edit = QLineEdit(os.path.join(working_directory, "event_flag_list.txt"))
        file_row.addWidget(self.flags_path_edit, 1)
        browse_flags_btn = QPushButton("Browse...")
        browse_flags_btn.clicked.connect(self.browse_flags_file)
        file_row.addWidget(browse_flags_btn)
        reload_btn = QPushButton("Reload")
        reload_btn.clicked.connect(self.reload_flags)
        file_row.addWidget(reload_btn)
        root.addLayout(file_row)

        script_row = QHBoxLayout()
        script_row.addWidget(QLabel("Trigger script (.js):"))
        self.script_path_edit = QLineEdit(os.path.join(working_directory, "event_trigger.js"))
        script_row.addWidget(self.script_path_edit, 1)
        browse_script_btn = QPushButton("Browse...")
        browse_script_btn.clicked.connect(self.browse_script_file)
        script_row.addWidget(browse_script_btn)
        root.addLayout(script_row)

        # --- splitter: known flags list | selection & action ---
        splitter = QSplitter(Qt.Horizontal)

        # left: known flags
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.addWidget(QLabel("Known flags"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Filter by id or name...")
        self.search_edit.textChanged.connect(self.filter_flags)
        left_layout.addWidget(self.search_edit)
        self.flags_list = QListWidget()
        self.flags_list.itemClicked.connect(self.flag_selected)
        left_layout.addWidget(self.flags_list, 1)
        splitter.addWidget(left)

        # right: manual entry + lock state + trigger + console
        right = QWidget()
        right_layout = QVBoxLayout(right)

        form_box = QGroupBox("Flag selection")
        form = QFormLayout(form_box)
        self.manual_id_edit = QLineEdit()
        self.manual_id_edit.setPlaceholderText("e.g. 1234 or 0x4D2 (overrides list selection)")
        form.addRow("Flag ID:", self.manual_id_edit)

        lock_row = QHBoxLayout()
        self.lock_group = QButtonGroup(self)
        self.radio_unlock = QRadioButton("0x0 (lock)")
        self.radio_lock = QRadioButton("0x1 (unlock)")
        self.radio_unlock.setChecked(True)
        self.lock_group.addButton(self.radio_unlock, 0)
        self.lock_group.addButton(self.radio_lock, 1)
        lock_row.addWidget(self.radio_unlock)
        lock_row.addWidget(self.radio_lock)
        lock_row.addStretch(1)
        form.addRow("Lock state:", lock_row)

        right_layout.addWidget(form_box)

        self.trigger_btn = QPushButton("Trigger flag")
        self.trigger_btn.setMinimumHeight(36)
        self.trigger_btn.clicked.connect(self.trigger_flag)
        right_layout.addWidget(self.trigger_btn)

        right_layout.addWidget(QLabel("Output:"))
        self.output_console = QPlainTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setFont(QFont("Consolas", 10))
        right_layout.addWidget(self.output_console, 1)

        splitter.addWidget(right)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

        self._all_flags = []
        self.reload_flags()

    # -- file browsing --
    def browse_flags_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select flags file", "", "Text files (*.txt);;All files (*)")
        if path:
            self.flags_path_edit.setText(path)
            self.reload_flags()

    def browse_script_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select trigger script", "", "JavaScript files (*.js);;All files (*)")
        if path:
            self.script_path_edit.setText(path)

    # -- flags list --
    def reload_flags(self):
        path = self.flags_path_edit.text().strip()
        self.flags_list.clear()
        self._all_flags = []
        if not path or not os.path.isfile(path):
            self.log(f"[!] Flags file not found: {path}")
            return
        try:
            self._all_flags = load_flags(path)
        except Exception as exc:
            self.log(f"[!] Failed to load flags file: {exc}")
            return
        self.populate_flags(self._all_flags)
        self.log(f"[i] Loaded {len(self._all_flags)} known flags from {path}")

    def populate_flags(self, flags):
        self.flags_list.clear()
        for flag_id, name in flags:
            item = QListWidgetItem(f"{hex(flag_id)}  -  {name}")
            item.setData(Qt.UserRole, flag_id)
            self.flags_list.addItem(item)

    def filter_flags(self, text):
        text = text.strip().lower()
        if not text:
            self.populate_flags(self._all_flags)
            return
        filtered = [
            (fid, name) for fid, name in self._all_flags
            if text in name.lower() or text in hex(fid).lower() or text in str(fid)
        ]
        self.populate_flags(filtered)

    def flag_selected(self, item):
        flag_id = item.data(Qt.UserRole)
        self.manual_id_edit.setText(hex(flag_id))

    # -- action --
    def trigger_flag(self):
        process_name = self.process_bar.process_name()
        if not process_name:
            QMessageBox.warning(self, "No process", "Please select or enter a target process name.")
            return

        script_path = self.script_path_edit.text().strip()
        if not os.path.isfile(script_path):
            QMessageBox.warning(self, "Script not found", f"Trigger script not found:\n{script_path}")
            return

        id_text = self.manual_id_edit.text().strip()
        if not id_text:
            selected = self.flags_list.currentItem()
            if selected is None:
                QMessageBox.warning(self, "No flag selected", "Enter a flag id or select one from the list.")
                return
            flag_id = selected.data(Qt.UserRole)
        else:
            try:
                flag_id = parse_int_auto(id_text)
            except ValueError:
                QMessageBox.warning(self, "Invalid flag ID", f"Could not parse flag id: {id_text}")
                return

        lock_state = self.lock_group.checkedId()  # 0 or 1

        self.trigger_btn.setEnabled(False)
        self.log(f"[>] Triggering flag {hex(flag_id)} with lock_state=0x{lock_state} on '{process_name}'...")

        self.worker = TriggerWorker(process_name, script_path, flag_id, lock_state)
        self.worker.finished_ok.connect(self.on_success)
        self.worker.finished_err.connect(self.on_error)
        self.worker.finished.connect(lambda: self.trigger_btn.setEnabled(True))
        self.worker.start()

    def on_success(self, message):
        self.log(f"[+] {message}")

    def on_error(self, message):
        self.log(f"[!] {message}")

    def log(self, text):
        self.output_console.appendPlainText(f"[{timestamp()}] {text}")


# --------------------------------------------------------------------------
# Logger tab
# --------------------------------------------------------------------------

class LoggerBridge(QObject):
    """Bridges Frida's background-thread message callback to the Qt GUI
    thread via signals (safe to emit from any thread)."""
    message_received = Signal(dict)
    session_detached = Signal(str)


class LoggerStartWorker(QThread):
    started_ok = Signal(object)   # emits the frida session
    started_err = Signal(str)

    def __init__(self, process_name, script_path, exclude_flags, on_message, parent=None):
        super().__init__(parent)
        self.process_name = process_name
        self.script_path = script_path
        self.exclude_flags = exclude_flags
        self.on_message = on_message

    def run(self):
        if frida is None:
            self.started_err.emit("The 'frida' package is not installed.")
            return
        try:
            session = frida.attach(self.process_name)
        except frida.ProcessNotFoundError:
            self.started_err.emit(
                f"Process '{self.process_name}' not found. Ensure the game is running."
            )
            return
        except Exception as exc:
            self.started_err.emit(f"Attach failed: {exc}")
            return

        try:
            with open(self.script_path, "r", encoding="utf-8") as f:
                script_code = f.read()
        except OSError as exc:
            session.detach()
            self.started_err.emit(f"Could not read script file: {exc}")
            return

        script_code = script_code.replace("{{PROCESS_NAME}}", self.process_name)
        script_code = script_code.replace("{{EXCLUDE_FLAGS}}", json.dumps(self.exclude_flags))

        try:
            script = session.create_script(script_code)
            script.on("message", self.on_message)
            script.load()
        except Exception as exc:
            session.detach()
            self.started_err.emit(f"Execution error: {exc}\n{traceback.format_exc()}")
            return

        self.started_ok.emit(session)


class LoggerTab(QWidget):
    def __init__(self, process_bar, parent=None):
        super().__init__(parent)
        self.process_bar = process_bar
        self.session = None
        self.start_worker = None
        self.seen_events = {}
        self.log_lines = []  # in-memory buffer, independent of the on-disk data file

        self.bridge = LoggerBridge()
        self.bridge.message_received.connect(self.handle_message)

        root = QVBoxLayout(self)

        script_row = QHBoxLayout()
        script_row.addWidget(QLabel("Logger script (.js):"))
        self.script_path_edit = QLineEdit(os.path.join(working_directory, "unlock_logger.js"))
        script_row.addWidget(self.script_path_edit, 1)
        browse_script_btn = QPushButton("Browse...")
        browse_script_btn.clicked.connect(self.browse_script_file)
        script_row.addWidget(browse_script_btn)
        root.addLayout(script_row)

        data_row = QHBoxLayout()
        data_row.addWidget(QLabel("Data file (appended live, same as CLI):"))
        self.data_path_edit = QLineEdit("event_flag_data.txt")
        data_row.addWidget(self.data_path_edit, 1)
        browse_data_btn = QPushButton("Browse...")
        browse_data_btn.clicked.connect(self.browse_data_file)
        data_row.addWidget(browse_data_btn)
        root.addLayout(data_row)

        splitter = QSplitter(Qt.Horizontal)

        # left: exclude list management
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.addWidget(QLabel("Exclude ID list"))
        self.exclude_list = QListWidget()
        self.exclude_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        for flag in DEFAULT_EXCLUDE_FLAGS:
            self.exclude_list.addItem(hex(flag))
        left_layout.addWidget(self.exclude_list, 1)

        add_row = QHBoxLayout()
        self.exclude_add_edit = QLineEdit()
        self.exclude_add_edit.setPlaceholderText("e.g. 0x7EE or 2030")
        self.exclude_add_edit.returnPressed.connect(self.add_exclude_id)
        add_row.addWidget(self.exclude_add_edit, 1)
        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self.add_exclude_id)
        add_row.addWidget(add_btn)
        left_layout.addLayout(add_row)

        remove_btn = QPushButton("Remove selected")
        remove_btn.clicked.connect(self.remove_selected_exclude)
        left_layout.addWidget(remove_btn)

        splitter.addWidget(left)

        # right: controls + console
        right = QWidget()
        right_layout = QVBoxLayout(right)

        controls_row = QHBoxLayout()
        self.toggle_btn = QPushButton("Start logging")
        self.toggle_btn.setMinimumHeight(36)
        self.toggle_btn.clicked.connect(self.toggle_logging)
        controls_row.addWidget(self.toggle_btn)

        self.status_label = QLabel("Stopped")
        self.status_label.setStyleSheet("color: gray;")
        controls_row.addWidget(self.status_label)
        controls_row.addStretch(1)

        save_btn = QPushButton("Save log as...")
        save_btn.clicked.connect(self.save_log_as)
        controls_row.addWidget(save_btn)

        clear_btn = QPushButton("Clear console")
        clear_btn.clicked.connect(self.clear_console)
        controls_row.addWidget(clear_btn)

        right_layout.addLayout(controls_row)

        right_layout.addWidget(QLabel("Live log:"))
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 10))
        right_layout.addWidget(self.console, 1)

        splitter.addWidget(right)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

    # -- file browsing --
    def browse_script_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select logger script", "", "JavaScript files (*.js);;All files (*)")
        if path:
            self.script_path_edit.setText(path)

    def browse_data_file(self):
        path, _ = QFileDialog.getSaveFileName(self, "Select data file", "event_flag_data.txt", "Text files (*.txt);;All files (*)")
        if path:
            self.data_path_edit.setText(path)

    # -- exclude list --
    def add_exclude_id(self):
        text = self.exclude_add_edit.text().strip()
        if not text:
            return
        try:
            flag_id = parse_int_auto(text)
        except ValueError:
            QMessageBox.warning(self, "Invalid ID", f"Could not parse id: {text}")
            return
        self.exclude_list.addItem(hex(flag_id))
        self.exclude_add_edit.clear()

    def remove_selected_exclude(self):
        for item in self.exclude_list.selectedItems():
            self.exclude_list.takeItem(self.exclude_list.row(item))

    def current_exclude_flags(self):
        flags = []
        for i in range(self.exclude_list.count()):
            text = self.exclude_list.item(i).text().strip()
            try:
                flags.append(parse_int_auto(text))
            except ValueError:
                continue
        return flags

    # -- logging control --
    def toggle_logging(self):
        if self.session is None:
            self.start_logging()
        else:
            self.stop_logging()

    def start_logging(self):
        process_name = self.process_bar.process_name()
        if not process_name:
            QMessageBox.warning(self, "No process", "Please select or enter a target process name.")
            return

        script_path = self.script_path_edit.text().strip()
        if not os.path.isfile(script_path):
            QMessageBox.warning(self, "Script not found", f"Logger script not found:\n{script_path}")
            return

        exclude_flags = self.current_exclude_flags()
        self.seen_events = {}

        self.toggle_btn.setEnabled(False)
        self.log(f"[>] Attaching to '{process_name}'...")

        # NOTE: the frida "message" callback runs on Frida's own thread.
        # We only touch self.bridge.emit() from it, which is thread-safe;
        # all GUI updates happen in handle_message() on the main thread.
        def on_message(message, data):
            if message.get("type") == "send":
                self.bridge.message_received.emit(message.get("payload", {}))

        self.start_worker = LoggerStartWorker(process_name, script_path, exclude_flags, on_message)
        self.start_worker.started_ok.connect(self.on_started)
        self.start_worker.started_err.connect(self.on_start_error)
        self.start_worker.finished.connect(lambda: self.toggle_btn.setEnabled(True))
        self.start_worker.start()

    def on_started(self, session):
        self.session = session
        self.toggle_btn.setText("Stop logging")
        self.status_label.setText("Logging active")
        self.status_label.setStyleSheet("color: green;")
        self.log("[+] Logging active.")

    def on_start_error(self, message):
        self.log(f"[!] {message}")

    def stop_logging(self):
        if self.session is not None:
            try:
                self.session.detach()
            except Exception as exc:
                self.log(f"[!] Error while detaching: {exc}")
            self.session = None
        self.toggle_btn.setText("Start logging")
        self.status_label.setText("Stopped")
        self.status_label.setStyleSheet("color: gray;")
        self.log("[*] Session detached.")

    # -- message handling (runs on GUI thread) --
    def handle_message(self, payload):
        payload_type = payload.get("type")

        if payload_type == "init":
            event_flag_man = payload.get("event_flag_man", "N/A")
            event_flag_start = payload.get("event_flag_start", "N/A")
            self.append_to_data_file(
                "--- SESSION INITIALIZED ---\n"
                f"event_flag_man: {event_flag_man} | event_flag_start: {event_flag_start}\n"
                "---------------------------"
            )
            self.log(f"[i] Initialized: event_flag_start={event_flag_start}, event flag man pointer {event_flag_man}")

        elif payload_type == "write_event":
            item_id = payload.get("item_id")
            address = payload.get("rcx")
            bit = payload.get("r10")
            event_flag_start_val = payload.get("event_flag_start")
            lock_state = payload.get("lock_state")

            if address and event_flag_start_val:
                try:
                    addr_int = int(address, 16) if isinstance(address, str) else address
                    start_int = (
                        int(event_flag_start_val, 16)
                        if isinstance(event_flag_start_val, str)
                        else event_flag_start_val
                    )
                    save_offset = hex(addr_int - start_int)
                except (ValueError, TypeError) as e:
                    self.log(f"[!] Error calculating offset: {e}")
                    save_offset = "N/A"

                item_str = str(item_id) if item_id is not None else "unknown"
                lock_str = str(lock_state) if lock_state is not None else "N/A"
                addr_str = str(address) if address is not None else "N/A"
                offset_str = str(save_offset) if save_offset is not None else "N/A"
                bit_str = str(bit) if bit is not None else "N/A"

                current_entry = (lock_str, addr_str, offset_str, bit_str)
                if self.seen_events.get(item_str) == current_entry:
                    return
                self.seen_events[item_str] = current_entry

                log_line = (
                    f"ItemID: {item_str:<12} | LockState: {lock_str:<5} | "
                    f"Offset: {addr_str} | SaveOffset: {offset_str} | Bit: {bit_str}"
                )
                self.append_to_data_file(log_line)
                self.log(f"[+] Logged: {item_str}, address {addr_str}, bit {bit}, lock state {lock_str}")
            else:
                self.log(f"[!] Missing data: address={address}, event_flag_start={event_flag_start_val}")

    # -- data file / buffer / console --
    def append_to_data_file(self, line):
        self.log_lines.append(line)
        path = self.data_path_edit.text().strip()
        if not path:
            return
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as exc:
            self.log(f"[!] Could not write to data file: {exc}")

    def save_log_as(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save log as", "event_flag_log_export.txt", "Text files (*.txt);;All files (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(self.log_lines) + ("\n" if self.log_lines else ""))
        except OSError as exc:
            QMessageBox.critical(self, "Save failed", str(exc))
            return
        self.log(f"[i] Saved {len(self.log_lines)} log entries to {path}")

    def clear_console(self):
        self.console.clear()

    def log(self, text):
        self.console.appendPlainText(f"[{timestamp()}] {text}")
        self.console.verticalScrollBar().setValue(self.console.verticalScrollBar().maximum())


# --------------------------------------------------------------------------
# Main window
# --------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Event Flag Manager")
        self.resize(1000, 650)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.process_bar = ProcessBar()
        layout.addWidget(self.process_bar)

        tabs = QTabWidget()
        self.trigger_tab = TriggerTab(self.process_bar)
        self.logger_tab = LoggerTab(self.process_bar)
        tabs.addTab(self.trigger_tab, "Event Flag Trigger")
        tabs.addTab(self.logger_tab, "Event Flag Logger")
        layout.addWidget(tabs, 1)

        if frida is None:
            QMessageBox.warning(
                self, "frida not found",
                "The 'frida' package is not installed. The UI will load, but "
                "trigger/logging actions will fail until you run:\n\n    pip install frida"
            )

    def closeEvent(self, event):
        # make sure we detach cleanly if the logger session is still active
        if self.logger_tab.session is not None:
            try:
                self.logger_tab.session.detach()
            except Exception:
                pass
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
