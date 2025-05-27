import sys
import os
import hashlib
import threading
import psutil

from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QTextEdit,
    QVBoxLayout, QFileDialog, QMessageBox, QHBoxLayout, QCheckBox, QProgressBar, QComboBox, QGroupBox, QFrame
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QPalette, QLinearGradient, QBrush, QColor
from PIL import Image
from monitor import start_monitoring
from recovery import recover_raw_files

class GuiCommunicator(QObject):
    log_signal = pyqtSignal(str)
    alert_signal = pyqtSignal(str, str)
    recovery_status_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)

class SmartGuardApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SmartGuard: File Corruption & Recovery System")
        self.setGeometry(200, 200, 900, 700)
        self.selected_file = None
        self.raw_output_folder = None
        self.dark_mode = True

        self.comm = GuiCommunicator()
        self.comm.log_signal.connect(self.log_message)
        self.comm.alert_signal.connect(self.show_alert)
        self.comm.recovery_status_signal.connect(self.update_recovery_status)
        self.comm.progress_signal.connect(self.update_progress)

        self.initUI()
        start_monitoring(self)
        self.set_high_priority()

    def initUI(self):
        self.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #8B5CF6, stop:0.3 #A855F7, stop:0.6 #C084FC, stop:1 #E879F9);
                color: #FFFFFF;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 13px;
            }
            
            QLabel {
                color: #FFFFFF;
                background: transparent;
            }
            
            QPushButton {
                background: rgba(255, 255, 255, 0.15);
                color: #FFFFFF;
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 12px;
                padding: 12px 20px;
                font-weight: 600;
                font-size: 13px;
                min-height: 20px;
            }
            
            QPushButton:hover {
                background: rgba(255, 255, 255, 0.25);
                border: 1px solid rgba(255, 255, 255, 0.4);
            }
            
            QPushButton:pressed {
                background: rgba(255, 255, 255, 0.1);
            }
            
            QPushButton:disabled {
                background: rgba(255, 255, 255, 0.05);
                color: rgba(255, 255, 255, 0.4);
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            QTextEdit {
                background: rgba(0, 0, 0, 0.3);
                color: #FFFFFF;
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 12px;
                padding: 15px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                selection-background-color: rgba(255, 255, 255, 0.2);
            }
            
            QProgressBar {
                background: rgba(0, 0, 0, 0.2);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 10px;
                text-align: center;
                color: #FFFFFF;
                font-weight: 600;
                height: 20px;
            }
            
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #FFFFFF, stop:1 #F0F8FF);
                border-radius: 8px;
                margin: 2px;
            }
            
            QGroupBox {
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 15px;
                margin-top: 15px;
                padding-top: 10px;
                font-weight: 600;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 5px 15px;
                color: #FFFFFF;
                font-weight: 700;
                font-size: 14px;
                background: rgba(255, 255, 255, 0.15);
                border-radius: 8px;
                margin-left: 10px;
            }
            
            QCheckBox {
                color: #FFFFFF;
                font-weight: 500;
                spacing: 8px;
            }
            
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border-radius: 4px;
                border: 2px solid rgba(255, 255, 255, 0.4);
                background: rgba(255, 255, 255, 0.1);
            }
            
            QCheckBox::indicator:checked {
                background: #FFFFFF;
                border: 2px solid #FFFFFF;
            }
            
            QComboBox {
                background: rgba(255, 255, 255, 0.15);
                color: #FFFFFF;
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 8px;
                padding: 8px 12px;
                font-weight: 500;
                min-width: 60px;
            }
            
            QComboBox:hover {
                background: rgba(255, 255, 255, 0.25);
                border: 1px solid rgba(255, 255, 255, 0.4);
            }
            
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            
            QComboBox::down-arrow {
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 6px solid #FFFFFF;
                margin-right: 5px;
            }
            
            QFrame {
                background: transparent;
                border: none;
            }
        """)

        # Main container with padding
        main_container = QFrame()
        main_layout = QVBoxLayout(main_container)
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)

        # Header Section
        header_frame = QFrame()
        header_layout = QVBoxLayout(header_frame)
        header_layout.setSpacing(8)
        
        header = QLabel("🛡️ SmartGuard")
        header.setFont(QFont("Segoe UI", 32, QFont.Bold))
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("color: #FFFFFF; font-weight: 800;")

        sub_label = QLabel("Advanced File Integrity • Deep System Scan • Raw Data Recovery")
        sub_label.setAlignment(Qt.AlignCenter)
        sub_label.setFont(QFont("Segoe UI", 12, QFont.Normal))
        sub_label.setStyleSheet("color: rgba(255, 255, 255, 0.8); font-weight: 400; margin-bottom: 10px;")

        header_layout.addWidget(header)
        header_layout.addWidget(sub_label)

        # File Operations Group
        file_group = QGroupBox("📂 File Operations")
        file_layout = QHBoxLayout()
        file_layout.setSpacing(15)
        file_layout.setContentsMargins(20, 25, 20, 20)

        self.select_button = QPushButton("📁 Choose File")
        self.select_button.clicked.connect(self.select_file)

        self.check_button = QPushButton("🔍 Verify Integrity")
        self.check_button.setEnabled(False)
        self.check_button.clicked.connect(self.start_check)

        self.monitor_button = QPushButton("👁️ Monitor Folder")
        self.monitor_button.clicked.connect(self.select_monitor_folder)

        file_layout.addWidget(self.select_button)
        file_layout.addWidget(self.check_button)
        file_layout.addWidget(self.monitor_button)
        file_group.setLayout(file_layout)

        # Raw Recovery Group
        recovery_group = QGroupBox("🔧 Raw Recovery System")
        recovery_layout = QVBoxLayout()
        recovery_layout.setContentsMargins(20, 25, 20, 20)
        recovery_layout.setSpacing(15)

        # Drive selection row
        drive_row = QHBoxLayout()
        drive_row.setSpacing(15)
        
        drive_label = QLabel("Target Drive:")
        drive_label.setStyleSheet("font-weight: 600; color: #FFFFFF;")
        
        self.drive_selector = QComboBox()
        self.drive_selector.addItems([d + ":" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(d + ":\\")])
        self.drive_selector.setFixedWidth(100)

        self.raw_output_button = QPushButton("📁 Set Output Folder")
        self.raw_output_button.clicked.connect(self.select_raw_output_folder)

        drive_row.addWidget(drive_label)
        drive_row.addWidget(self.drive_selector)
        drive_row.addStretch()
        drive_row.addWidget(self.raw_output_button)

        # Recovery button row
        recovery_button_row = QHBoxLayout()
        self.raw_recover_button = QPushButton("🚀 Start Deep Recovery")
        self.raw_recover_button.clicked.connect(self.trigger_raw_recovery)
        self.raw_recover_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(255, 255, 255, 0.2), stop:1 rgba(255, 255, 255, 0.3));
                font-weight: 700;
                font-size: 14px;
                padding: 15px 25px;
            }
        """)
        
        recovery_button_row.addStretch()
        recovery_button_row.addWidget(self.raw_recover_button)
        recovery_button_row.addStretch()

        recovery_layout.addLayout(drive_row)
        recovery_layout.addLayout(recovery_button_row)
        recovery_group.setLayout(recovery_layout)

        # Progress Section
        progress_frame = QFrame()
        progress_layout = QVBoxLayout(progress_frame)
        progress_layout.setSpacing(10)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)  # Always visible now

        self.recovery_status = QLabel("📊 Status: Ready for Operations")
        self.recovery_status.setAlignment(Qt.AlignCenter)
        self.recovery_status.setStyleSheet("""
            color: #FFFFFF; 
            font-weight: 600; 
            font-size: 14px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 8px 15px;
        """)

        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.recovery_status)

        # Logs Section
        logs_group = QGroupBox("📋 System Logs")
        logs_layout = QVBoxLayout()
        logs_layout.setContentsMargins(20, 25, 20, 20)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setFont(QFont("Consolas", 11))
        self.log_box.setMinimumHeight(200)
        self.log_box.append("🚀 SmartGuard initialized successfully")
        self.log_box.append("💡 Ready to protect and recover your files")

        logs_layout.addWidget(self.log_box)
        logs_group.setLayout(logs_layout)

        # Preferences Group
        settings_group = QGroupBox("⚙️ System Preferences")
        settings_layout = QHBoxLayout()
        settings_layout.setContentsMargins(20, 25, 20, 20)

        self.theme_switch = QCheckBox("🌙 Dark Mode Enhanced")
        self.theme_switch.setChecked(self.dark_mode)
        self.theme_switch.stateChanged.connect(self.toggle_theme)

        settings_layout.addStretch()
        settings_layout.addWidget(self.theme_switch)
        settings_group.setLayout(settings_layout)

        # Add all sections to main layout
        main_layout.addWidget(header_frame)
        main_layout.addWidget(file_group)
        main_layout.addWidget(recovery_group)
        main_layout.addWidget(progress_frame)
        main_layout.addWidget(logs_group)
        main_layout.addWidget(settings_group)

        # Set the main layout
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(main_container)
        self.setLayout(layout)

    def toggle_theme(self, state):
        # For now, we'll keep the modern purple theme
        # You can implement light theme switching here if needed
        pass

    def set_high_priority(self):
        try:
            pid = os.getpid()
            p = psutil.Process(pid)
            p.nice(psutil.REALTIME_PRIORITY_CLASS)
            self.comm.log_signal.emit("⚡ [PRIORITY] Process priority elevated to REALTIME")
        except Exception as e:
            self.comm.log_signal.emit(f"⚠️ [WARNING] Could not set priority: {e}")

    def log_message(self, text):
        self.log_box.append(text)

    def update_recovery_status(self, message):
        self.recovery_status.setText(f"📊 Status: {message}")

    def update_progress(self, value):
        self.progress_bar.setValue(value)
        if value > 0:
            self.progress_bar.setFormat(f"Progress: {value}%")
        else:
            self.progress_bar.setFormat("Ready...")

    def select_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select a File")
        if path:
            self.selected_file = path
            self.comm.log_signal.emit(f"📄 [SELECTED] File: {os.path.basename(path)}")
            self.comm.log_signal.emit(f"📍 [PATH] {path}")
            self.check_button.setEnabled(True)
            self.update_progress(10)

    def select_monitor_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select Folder to Monitor")
        if path:
            self.comm.log_signal.emit(f"👁️ [MONITOR] Folder set: {path}")
            start_monitoring(self, path)
            self.update_progress(15)

    def select_raw_output_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select Output Folder for Raw Files")
        if path:
            self.raw_output_folder = path
            self.comm.log_signal.emit(f"💾 [OUTPUT] Raw recovery folder: {path}")
            self.update_progress(20)

    def start_check(self):
        if self.selected_file:
            self.comm.log_signal.emit("🔍 [ACTION] Initiating comprehensive file analysis...")
            self.update_progress(30)
            thread = threading.Thread(target=self.check_file_corruption, args=(self.selected_file,))
            thread.start()

    def check_file_corruption(self, path=None):
        try:
            file_path = path or self.selected_file
            size = os.path.getsize(file_path)
            self.update_progress(50)
            
            with open(file_path, 'rb') as f:
                data = f.read()
                file_hash = hashlib.sha256(data).hexdigest()

            self.comm.log_signal.emit(f"📏 File Size: {size:,} bytes")
            self.comm.log_signal.emit(f"🔐 SHA-256: {file_hash}")
            self.update_progress(80)

            if self.check_corruption(file_path):
                self.comm.log_signal.emit("❌ [RESULT] File corruption detected!")
                self.comm.alert_signal.emit("File corruption detected! Attempt recovery?", file_path)
                self.update_progress(100)
            else:
                self.comm.log_signal.emit("✅ [RESULT] File integrity verified - No corruption found")
                self.update_progress(100)
        except Exception as e:
            self.comm.log_signal.emit(f"💥 [ERROR] Analysis failed: {e}")
            self.update_progress(0)

    def check_corruption(self, file_path):
        try:
            size = os.path.getsize(file_path)
            if size == 0:
                return True
            ext = os.path.splitext(file_path)[1].lower()
            if ext in ['.jpg', '.jpeg', '.png']:
                with Image.open(file_path) as img:
                    img.verify()
                return False
            elif ext == '.pdf':
                with open(file_path, 'rb') as f:
                    return not f.read(4).startswith(b'%PDF')
            elif ext in ['.zip', '.docx']:
                with open(file_path, 'rb') as f:
                    return not f.read(4).startswith(b'PK\x03\x04')
            return False
        except Exception:
            return True

    def show_alert(self, message, file_path):
        reply = QMessageBox.question(self, "🚨 Corruption Alert", message,
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if reply == QMessageBox.Yes:
            self.log_message(f"🔧 [RECOVERY] Initiating recovery for: {os.path.basename(file_path)}")
            self.comm.recovery_status_signal.emit("Recovery process started...")
            self.update_progress(0)

    def trigger_raw_recovery(self):
        if not self.raw_output_folder:
            self.comm.log_signal.emit("⚠️ [ERROR] Please configure output folder for raw recovery")
            return
        drive = self.drive_selector.currentText().strip(":")
        self.comm.log_signal.emit(f"🚀 [RECOVERY] Starting deep scan on drive {drive}:")
        self.update_progress(0)
        thread = threading.Thread(target=recover_raw_files, args=(self.comm, drive, self.raw_output_folder))
        thread.start()

    def closeEvent(self, event):
        reply = QMessageBox.question(self, "Exit SmartGuard", 
                                   "Are you sure you want to exit SmartGuard?",
                                   QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.comm.log_signal.emit("👋 [SHUTDOWN] SmartGuard shutting down...")
            event.accept()
            QApplication.quit()
        else:
            event.ignore()

if __name__ == "__main__":
    import ctypes
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    if not is_admin():
        try:
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        except Exception as e:
            print(f"Failed to elevate privileges: {e}")
        sys.exit(0)
    else:
        app = QApplication(sys.argv)
        window = SmartGuardApp()
        window.show()
        sys.exit(app.exec_())