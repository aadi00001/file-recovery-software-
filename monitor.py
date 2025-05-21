import os
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class DownloadMonitor(FileSystemEventHandler):
    def __init__(self, gui_ref):
        self.gui = gui_ref

    def on_created(self, event):    
        if not event.is_directory:
            filepath = event.src_path
            filename = os.path.basename(filepath)
            self.gui.comm.log_signal.emit(f"[MONITOR] New file detected: {filename}")
            if self.gui.check_corruption(filepath):
                self.gui.comm.log_signal.emit(f"[WARNING] Corruption detected in: {filename}")
                self.gui.comm.alert_signal.emit(f"{filename} may be corrupted. Do you want to attempt recovery?", filepath)

def start_monitoring(gui_ref, folder_path=None):
    if folder_path is None:
        folder_path = os.path.join(os.environ["USERPROFILE"], "Downloads")
    observer = Observer()
    monitor = DownloadMonitor(gui_ref)
    observer.schedule(monitor, folder_path, recursive=False)
    observer.start()
    gui_ref.comm.log_signal.emit(f"[INFO] Monitoring started at: {folder_path}")

    thread = threading.Thread(target=observer.join, daemon=True)
    thread.start()
    # We run this in a daemon thread, so it doesn’t block the main GUI or crash the app.