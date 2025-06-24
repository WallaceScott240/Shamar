import os
import sys
import json
import hashlib
import time
import csv
import threading
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QFileDialog,
    QLabel, QStatusBar, QProgressBar, QSystemTrayIcon, QMenu,
    QAction, QStyle, QMessageBox, QAbstractItemView, QHeaderView, QSpinBox
)
from PyQt5.QtCore import Qt, QTimer, QObject, pyqtSignal
from PyQt5.QtGui import QIcon, QColor, QFont

# Dark theme stylesheet
DARK_STYLE = """
QWidget {
    background-color: #2D2D30;
    color: #FFFFFF;
    font-family: Segoe UI;
}
QMainWindow::separator {
    background-color: #1E1E1E;
    width: 4px;
}
QTableWidget {
    gridline-color: #3F3F46;
    background-color: #1E1E1E;
    alternate-background-color: #252526;
}
QHeaderView::section {
    background-color: #252526;
    padding: 4px;
    border: none;
    border-bottom: 1px solid #3F3F46;
}
QProgressBar {
    border: 1px solid #3F3F46;
    border-radius: 3px;
    text-align: center;
    color: #FFFFFF;
}
QProgressBar::chunk {
    background-color: #007ACC;
}
QPushButton {
    background-color: #3F3F46;
    border: 1px solid #3F3F46;
    border-radius: 3px;
    padding: 5px 10px;
    color: #FFFFFF;
}
QPushButton:hover {
    background-color: #5D5D66;
}
QPushButton:pressed {
    background-color: #007ACC;
}
QMenu {
    background-color: #252526;
    color: #FFFFFF;
    border: 1px solid #3F3F46;
}
QMenu::item:selected {
    background-color: #007ACC;
}
QSpinBox {
    background-color: #3F3F46;
    color: #FFFFFF;
    border: 1px solid #3F3F46;
    border-radius: 3px;
    padding: 2px;
}
"""

LIGHT_STYLE = """
QWidget {
    background-color: #F0F0F0;
    color: #000000;
    font-family: Segoe UI;
}
QMainWindow::separator {
    background-color: #D0D0D0;
    width: 4px;
}
QTableWidget {
    gridline-color: #C0C0C0;
    background-color: #FFFFFF;
    alternate-background-color: #F0F0F0;
}
QHeaderView::section {
    background-color: #E0E0E0;
    padding: 4px;
    border: none;
    border-bottom: 1px solid #C0C0C0;
}
QProgressBar {
    border: 1px solid #C0C0C0;
    border-radius: 3px;
    text-align: center;
    color: #000000;
}
QProgressBar::chunk {
    background-color: #1E90FF;
}
QPushButton {
    background-color: #E0E0E0;
    border: 1px solid #C0C0C0;
    border-radius: 3px;
    padding: 5px 10px;
    color: #000000;
}
QPushButton:hover {
    background-color: #D0D0D0;
}
QPushButton:pressed {
    background-color: #1E90FF;
    color: #FFFFFF;
}
QMenu {
    background-color: #FFFFFF;
    color: #000000;
    border: 1px solid #C0C0C0;
}
QMenu::item:selected {
    background-color: #1E90FF;
    color: #FFFFFF;
}
QSpinBox {
    background-color: #FFFFFF;
    color: #000000;
    border: 1px solid #C0C0C0;
    border-radius: 3px;
    padding: 2px;
}
"""

class FileScannerThread(QObject):
    progress_updated = pyqtSignal(int)
    scanning_complete = pyqtSignal(dict, list)
    error_occurred = pyqtSignal(str)

    def __init__(self, paths, baseline):
        super().__init__()
        self.paths = paths
        self.baseline = baseline
        self.running = True

    def run(self):
        try:
            current_hashes = {}
            results = []
            total_files = self.count_files()
            scanned_files = 0
            
            for path in self.paths:
                if not self.running:
                    return
                    
                if os.path.isfile(path):
                    self.process_file(path, current_hashes, results)
                    scanned_files += 1
                    progress = int((scanned_files / total_files) * 100) if total_files > 0 else 0
                    self.progress_updated.emit(progress)
                    
                elif os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for file in files:
                            if not self.running:
                                return
                            file_path = os.path.join(root, file)
                            self.process_file(file_path, current_hashes, results)
                            scanned_files += 1
                            progress = int((scanned_files / total_files) * 100) if total_files > 0 else 0
                            self.progress_updated.emit(progress)
            
            self.scanning_complete.emit(current_hashes, results)
        except Exception as e:
            self.error_occurred.emit(str(e))

    def count_files(self):
        count = 0
        for path in self.paths:
            if os.path.isfile(path):
                count += 1
            elif os.path.isdir(path):
                for _, _, files in os.walk(path):
                    count += len(files)
        return count

    def process_file(self, file_path, current_hashes, results):
        try:
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            last_modified = file_stat.st_mtime

            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    if not self.running:
                        return
                    sha256.update(chunk)
            file_hash = sha256.hexdigest()

            current_hashes[file_path] = {
                'hash': file_hash,
                'size': file_size,
                'last_modified': last_modified
            }

            status = "New"
            if file_path in self.baseline:
                if file_hash != self.baseline[file_path]['hash']:
                    status = "Modified"
                else:
                    status = "Unchanged"

            results.append({
                'status': status,
                'path': file_path,
                'size': file_size,
                'last_modified': last_modified,
                'hash': file_hash
            })

        except Exception as e:
            # Skip files we can't read but continue scanning
            pass

    def stop(self):
        self.running = False


class FileIntegrityChecker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Integrity Checker")
        self.setGeometry(100, 100, 1000, 600)
        
        # Initialize variables
        self.baseline = {}
        self.current_files = {}
        self.paths = []
        self.scan_thread = None
        self.thread = None
        self.tray_icon = None
        self.continuous_monitoring = False
        self.monitoring_timer = QTimer()
        self.monitoring_timer.timeout.connect(self.start_scan)
        self.dark_theme = True
        
        # Setup UI
        self.setup_ui()
        self.apply_dark_theme()
        self.create_tray_icon()
        
    def setup_ui(self):
        # Central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Top buttons
        button_layout = QHBoxLayout()
        
        self.select_btn = QPushButton("Select Files/Folders")
        self.select_btn.clicked.connect(self.select_files)
        button_layout.addWidget(self.select_btn)
        
        self.scan_btn = QPushButton("Scan Now")
        self.scan_btn.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_btn)
        
        self.load_btn = QPushButton("Load Baseline")
        self.load_btn.clicked.connect(self.load_baseline)
        button_layout.addWidget(self.load_btn)
        
        self.save_btn = QPushButton("Save Baseline")
        self.save_btn.clicked.connect(self.save_baseline)
        button_layout.addWidget(self.save_btn)
        
        self.clear_btn = QPushButton("Clear Results")
        self.clear_btn.clicked.connect(self.clear_results)
        button_layout.addWidget(self.clear_btn)
        
        self.export_btn = QPushButton("Export Report")
        self.export_btn.clicked.connect(self.export_report)
        button_layout.addWidget(self.export_btn)
        
        self.theme_btn = QPushButton("Toggle Theme")
        self.theme_btn.clicked.connect(self.toggle_theme)
        button_layout.addWidget(self.theme_btn)
        
        main_layout.addLayout(button_layout)
        
        # Monitoring controls
        monitor_layout = QHBoxLayout()
        self.monitor_label = QLabel("Continuous Monitoring:")
        monitor_layout.addWidget(self.monitor_label)
        
        self.monitor_toggle = QPushButton("Start Monitoring")
        self.monitor_toggle.clicked.connect(self.toggle_monitoring)
        monitor_layout.addWidget(self.monitor_toggle)
        
        self.interval_label = QLabel("Interval (seconds):")
        monitor_layout.addWidget(self.interval_label)
        
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(5, 3600)
        self.interval_spin.setValue(30)
        monitor_layout.addWidget(self.interval_spin)
        
        monitor_layout.addStretch()
        main_layout.addLayout(monitor_layout)
        
        # Results table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Status", "File Path", "Size", "Last Modified", "Hash"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        main_layout.addWidget(self.table)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(200)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label, 1)
        
    def create_tray_icon(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
            
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        
        tray_menu = QMenu()
        scan_action = tray_menu.addAction("Scan Now")
        scan_action.triggered.connect(self.start_scan)
        
        monitor_action = tray_menu.addAction("Start Monitoring")
        monitor_action.triggered.connect(self.toggle_monitoring)
        
        quit_action = tray_menu.addAction("Exit")
        quit_action.triggered.connect(self.close)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        self.tray_icon.activated.connect(self.tray_icon_activated)
        
    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.showNormal()
            self.activateWindow()
            
    def apply_dark_theme(self):
        self.dark_theme = True
        self.setStyleSheet(DARK_STYLE)
        
    def apply_light_theme(self):
        self.dark_theme = False
        self.setStyleSheet(LIGHT_STYLE)
        
    def toggle_theme(self):
        if self.dark_theme:
            self.apply_light_theme()
        else:
            self.apply_dark_theme()
            
    def select_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        
        paths = []
        if files:
            paths.extend(files)
        if folder:
            paths.append(folder)
            
        if paths:
            self.paths = paths
            self.status_label.setText(f"{len(paths)} locations selected")
            
    def load_baseline(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Baseline", "", "JSON Files (*.json)"
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    self.baseline = json.load(f)
                self.status_label.setText(f"Baseline loaded: {len(self.baseline)} files")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load baseline: {str(e)}")
                
    def save_baseline(self):
        if not self.current_files:
            QMessageBox.warning(self, "Warning", "No scan results to save")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Baseline", "baseline.json", "JSON Files (*.json)"
        )
        if file_path:
            try:
                # Only save files that were successfully scanned
                baseline_to_save = {}
                for path, data in self.current_files.items():
                    baseline_to_save[path] = {
                        'hash': data['hash'],
                        'size': data['size'],
                        'last_modified': data['last_modified']
                    }
                
                with open(file_path, 'w') as f:
                    json.dump(baseline_to_save, f, indent=4)
                self.status_label.setText(f"Baseline saved: {len(baseline_to_save)} files")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save baseline: {str(e)}")
                
    def start_scan(self):
        if not self.paths:
            QMessageBox.warning(self, "Warning", "Please select files or folders first")
            return
            
        if self.scan_thread and self.scan_thread.running:
            QMessageBox.warning(self, "Warning", "Scan already in progress")
            return
            
        # Clear previous results but keep baseline
        self.table.setRowCount(0)
        self.current_files = {}
        
        # Setup thread
        self.scan_thread = FileScannerThread(self.paths, self.baseline)
        self.thread = threading.Thread(target=self.scan_thread.run)
        
        # Connect signals
        self.scan_thread.progress_updated.connect(self.update_progress)
        self.scan_thread.scanning_complete.connect(self.scan_completed)
        self.scan_thread.error_occurred.connect(self.show_error)
        
        # Start thread
        self.thread.start()
        
        self.status_label.setText("Scanning files...")
        self.scan_btn.setEnabled(False)
        
    def update_progress(self, value):
        self.progress_bar.setValue(value)
        
    def scan_completed(self, current_hashes, results):
        self.scan_btn.setEnabled(True)
        self.progress_bar.setValue(100)
        
        # Process results
        self.current_files = current_hashes
        
        # Find missing files
        baseline_paths = set(self.baseline.keys())
        current_paths = set(self.current_files.keys())
        missing_paths = baseline_paths - current_paths
        
        for path in missing_paths:
            results.append({
                'status': 'Missing',
                'path': path,
                'size': self.baseline[path]['size'],
                'last_modified': self.baseline[path]['last_modified'],
                'hash': self.baseline[path]['hash']
            })
        
        # Update table
        self.table.setRowCount(len(results))
        for row, data in enumerate(results):
            # Status with color coding
            status_item = QTableWidgetItem(data['status'])
            if data['status'] == 'Modified':
                status_item.setBackground(QColor(255, 165, 0))  # Orange
            elif data['status'] == 'New':
                status_item.setBackground(QColor(50, 205, 50))  # Green
            elif data['status'] == 'Missing':
                status_item.setBackground(QColor(220, 20, 60))  # Red
            
            self.table.setItem(row, 0, status_item)
            self.table.setItem(row, 1, QTableWidgetItem(data['path']))
            self.table.setItem(row, 2, QTableWidgetItem(self.format_size(data['size'])))
            self.table.setItem(row, 3, QTableWidgetItem(
                datetime.fromtimestamp(data['last_modified']).strftime('%Y-%m-%d %H:%M:%S')))
            self.table.setItem(row, 4, QTableWidgetItem(data['hash']))
        
        # Update status
        file_count = len(results)
        modified_count = sum(1 for r in results if r['status'] == 'Modified')
        new_count = sum(1 for r in results if r['status'] == 'New')
        missing_count = sum(1 for r in results if r['status'] == 'Missing')
        
        self.status_label.setText(
            f"Scan complete: {file_count} files | "
            f"Modified: {modified_count} | "
            f"New: {new_count} | "
            f"Missing: {missing_count}"
        )
        
    def show_error(self, message):
        self.scan_btn.setEnabled(True)
        QMessageBox.critical(self, "Scan Error", f"An error occurred during scanning:\n{message}")
        self.status_label.setText("Scan failed")
        
    def format_size(self, size):
        # Convert bytes to human-readable format
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
        
    def toggle_monitoring(self):
        if self.continuous_monitoring:
            self.monitoring_timer.stop()
            self.continuous_monitoring = False
            self.monitor_toggle.setText("Start Monitoring")
            self.status_label.setText("Continuous monitoring stopped")
        else:
            interval = self.interval_spin.value() * 1000  # Convert to milliseconds
            self.monitoring_timer.start(interval)
            self.continuous_monitoring = True
            self.monitor_toggle.setText("Stop Monitoring")
            self.status_label.setText(f"Continuous monitoring started ({self.interval_spin.value()}s interval)")
            
    def clear_results(self):
        self.table.setRowCount(0)
        self.status_label.setText("Results cleared")
        
    def export_report(self):
        if self.table.rowCount() == 0:
            QMessageBox.warning(self, "Warning", "No results to export")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", "integrity_report.csv", "CSV Files (*.csv);;Text Files (*.txt)"
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                if file_path.endswith('.csv'):
                    writer = csv.writer(f)
                    writer.writerow(['Status', 'File Path', 'Size', 'Last Modified', 'Hash'])
                    for row in range(self.table.rowCount()):
                        writer.writerow([
                            self.table.item(row, 0).text(),
                            self.table.item(row, 1).text(),
                            self.table.item(row, 2).text(),
                            self.table.item(row, 3).text(),
                            self.table.item(row, 4).text()
                        ])
                else:
                    f.write("File Integrity Report\n")
                    f.write("="*50 + "\n\n")
                    for row in range(self.table.rowCount()):
                        f.write(f"Status: {self.table.item(row, 0).text()}\n")
                        f.write(f"File: {self.table.item(row, 1).text()}\n")
                        f.write(f"Size: {self.table.item(row, 2).text()}\n")
                        f.write(f"Modified: {self.table.item(row, 3).text()}\n")
                        f.write(f"Hash: {self.table.item(row, 4).text()}\n")
                        f.write("-"*50 + "\n")
                    
            self.status_label.setText(f"Report exported to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export report: {str(e)}")
            
    def closeEvent(self, event):
        # Stop any running threads
        if self.scan_thread:
            self.scan_thread.stop()
            
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1.0)
            
        # Stop monitoring
        if self.continuous_monitoring:
            self.monitoring_timer.stop()
            
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = FileIntegrityChecker()
    window.show()
    sys.exit(app.exec_())