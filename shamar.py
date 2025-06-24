import os
import hashlib
import json
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QTextEdit, QTreeWidget, QTreeWidgetItem, QFileDialog,
    QSplitter, QStatusBar, QProgressBar, QMessageBox
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QColor, QIcon, QPalette

HASH_FILE = "file_hashes.json"

class FileIntegrityGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Integrity Monitor")
        self.setGeometry(100, 100, 900, 700)
        
        # Set application style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2D2D30;
            }
            QWidget {
                background-color: #2D2D30;
                color: #DCDCDC;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QLabel {
                color: #DCDCDC;
                font-weight: normal;
            }
            QLineEdit {
                background-color: #3D3D40;
                border: 1px solid #555555;
                border-radius: 3px;
                padding: 5px;
                color: #FFFFFF;
            }
            QPushButton {
                background-color: #0078D7;
                color: #FFFFFF;
                border: none;
                border-radius: 3px;
                padding: 7px 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1C97EA;
            }
            QPushButton:disabled {
                background-color: #5A5A5A;
                color: #AAAAAA;
            }
            QTreeWidget {
                background-color: #252526;
                border: 1px solid #555555;
                alternate-background-color: #2A2A2A;
                color: #DCDCDC;
            }
            QHeaderView::section {
                background-color: #3C3C3D;
                padding: 5px;
                border: none;
            }
            QTextEdit {
                background-color: #252526;
                border: 1px solid #555555;
                color: #DCDCDC;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 3px;
                text-align: center;
                background-color: #1E1E1E;
            }
            QProgressBar::chunk {
                background-color: #0078D7;
                width: 10px;
            }
        """)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 10)
        main_layout.setSpacing(15)
        
        # Create title
        title = QLabel("File Integrity Monitor")
        title_font = QFont("Segoe UI", 18, QFont.Bold)
        title.setFont(title_font)
        title.setStyleSheet("color: #4EC9B0; padding-bottom: 10px;")
        main_layout.addWidget(title)
        
        # Create description
        desc = QLabel("Monitor file changes by comparing SHA-256 hashes. Select a directory to scan.")
        desc.setFont(QFont("Segoe UI", 9))
        desc.setStyleSheet("color: #AAAAAA; padding-bottom: 10px;")
        main_layout.addWidget(desc)
        
        # Directory selection
        dir_layout = QHBoxLayout()
        dir_layout.setSpacing(10)
        
        self.dir_label = QLabel("Directory:")
        self.dir_label.setFont(QFont("Segoe UI", 10))
        dir_layout.addWidget(self.dir_label)
        
        self.dir_entry = QLineEdit()
        self.dir_entry.setPlaceholderText("Select a directory to monitor...")
        self.dir_entry.setFont(QFont("Segoe UI", 10))
        dir_layout.addWidget(self.dir_entry, 1)
        
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.setFont(QFont("Segoe UI", 9))
        self.browse_btn.setIcon(QIcon.fromTheme("folder"))
        self.browse_btn.setFixedWidth(100)
        self.browse_btn.clicked.connect(self.browse_directory)
        dir_layout.addWidget(self.browse_btn)
        
        self.scan_btn = QPushButton("Scan Directory")
        self.scan_btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self.scan_btn.setIcon(QIcon.fromTheme("search"))
        self.scan_btn.setFixedWidth(150)
        self.scan_btn.setEnabled(False)
        self.scan_btn.clicked.connect(self.start_scan)
        dir_layout.addWidget(self.scan_btn)
        
        main_layout.addLayout(dir_layout)
        
        # Create splitter for results and log
        splitter = QSplitter(Qt.Vertical)
        main_layout.addWidget(splitter, 1)
        
        # Results panel
        results_widget = QWidget()
        results_layout = QVBoxLayout(results_widget)
        results_layout.setContentsMargins(0, 0, 0, 0)
        
        results_header = QLabel("Scan Results")
        results_header.setFont(QFont("Segoe UI", 11, QFont.Bold))
        results_header.setStyleSheet("color: #4EC9B0; padding-bottom: 5px;")
        results_layout.addWidget(results_header)
        
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["Status", "File Path", "Previous Hash", "Current Hash"])
        self.results_tree.setFont(QFont("Segoe UI", 9))
        self.results_tree.setColumnWidth(0, 100)
        self.results_tree.setColumnWidth(1, 350)
        self.results_tree.setColumnWidth(2, 200)
        self.results_tree.setColumnWidth(3, 200)
        self.results_tree.setSortingEnabled(True)
        results_layout.addWidget(self.results_tree, 1)
        
        splitter.addWidget(results_widget)
        
        # Log panel
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        log_layout.setContentsMargins(0, 0, 0, 0)
        
        log_header = QLabel("Scan Log")
        log_header.setFont(QFont("Segoe UI", 11, QFont.Bold))
        log_header.setStyleSheet("color: #4EC9B0; padding-bottom: 5px;")
        log_layout.addWidget(log_header)
        
        self.log_text = QTextEdit()
        self.log_text.setFont(QFont("Segoe UI", 9))
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text, 1)
        
        splitter.addWidget(log_widget)
        
        # Set initial splitter sizes
        splitter.setSizes([400, 200])
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(200)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)
        
        # Initialize variables
        self.directory = ""
        self.old_hashes = {}
        self.new_hashes = {}
        
        # Update UI
        self.update_ui()
    
    def update_ui(self):
        """Update UI elements based on current state"""
        has_directory = bool(self.dir_entry.text().strip())
        self.scan_btn.setEnabled(has_directory)
    
    def browse_directory(self):
        """Open directory dialog to select directory"""
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.dir_entry.setText(directory)
            self.update_ui()
            self.log_text.append(f"[INFO] Selected directory: {directory}")
    
    def start_scan(self):
        """Start scanning the selected directory"""
        self.directory = self.dir_entry.text().strip()
        if not self.directory:
            QMessageBox.warning(self, "Error", "Please select a directory first")
            return
        
        if not os.path.isdir(self.directory):
            QMessageBox.warning(self, "Error", "The selected directory does not exist")
            return
        
        # Clear previous results
        self.results_tree.clear()
        self.log_text.append(f"[INFO] Starting scan of directory: {self.directory}")
        self.log_text.append(f"[INFO] Loading previous hashes...")
        
        # Load previous hashes
        self.old_hashes = self.load_previous_hashes()
        
        self.log_text.append(f"[INFO] Found {len(self.old_hashes)} previously tracked files")
        self.log_text.append(f"[INFO] Scanning directory...")
        
        # Start scanning in a separate thread would be better, 
        # but for simplicity we'll do it in the main thread with progress updates
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.status_label.setText("Scanning directory...")
        QApplication.processEvents()  # Update UI
        
        # Scan directory
        self.new_hashes = self.scan_directory(self.directory)
        
        # Compare hashes
        changed, new_files, deleted_files = self.compare_hashes(self.old_hashes, self.new_hashes)
        
        # Update results
        self.update_results(changed, new_files, deleted_files)
        
        # Save new hashes
        self.save_hashes(self.new_hashes)
        
        # Update log and status
        self.log_text.append(f"[INFO] Scan completed. Found: "
                            f"{len(changed)} modified, "
                            f"{len(new_files)} new, "
                            f"{len(deleted_files)} deleted files")
        self.log_text.append(f"[INFO] Hash database updated")
        
        # Show summary
        scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.log_text.append(f"[INFO] Scan completed on {scan_time}")
        self.status_label.setText(f"Scan completed: {len(changed)} modified, {len(new_files)} new, {len(deleted_files)} deleted")
        
        # Reset progress bar
        self.progress_bar.setVisible(False)
    
    def calculate_hash(self, filepath):
        """Calculate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (FileNotFoundError, PermissionError, OSError) as e:
            self.log_text.append(f"[ERROR] Could not read file {filepath}: {str(e)}")
            return None
    
    def scan_directory(self, directory):
        """Scan directory and return a dictionary of file paths and hashes."""
        file_hashes = {}
        total_files = 0
        for root, _, files in os.walk(directory):
            for file in files:
                total_files += 1
        
        processed = 0
        self.progress_bar.setRange(0, total_files)
        
        for root, _, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                hash_val = self.calculate_hash(filepath)
                if hash_val:
                    file_hashes[filepath] = hash_val
                
                processed += 1
                self.progress_bar.setValue(processed)
                if processed % 50 == 0:  # Update status periodically
                    self.status_label.setText(f"Scanning... {processed}/{total_files} files processed")
                    QApplication.processEvents()
        
        return file_hashes
    
    def load_previous_hashes(self):
        """Load saved hash values from file."""
        if os.path.exists(HASH_FILE):
            try:
                with open(HASH_FILE, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                self.log_text.append(f"[WARNING] Could not load hash file: {str(e)}")
        return {}
    
    def save_hashes(self, hashes):
        """Save current hash values to file."""
        try:
            with open(HASH_FILE, 'w') as f:
                json.dump(hashes, f, indent=4)
        except IOError as e:
            self.log_text.append(f"[ERROR] Could not save hash file: {str(e)}")
    
    def compare_hashes(self, old_hashes, new_hashes):
        """Compare old and new hashes and report changes."""
        changed = []
        new_files = []
        deleted_files = []

        for path, new_hash in new_hashes.items():
            old_hash = old_hashes.get(path)
            if old_hash is None:
                new_files.append(path)
            elif old_hash != new_hash:
                changed.append(path)

        for path in old_hashes:
            if path not in new_hashes:
                deleted_files.append(path)

        return changed, new_files, deleted_files
    
    def update_results(self, changed, new_files, deleted_files):
        """Update the results tree with the scan findings"""
        # Add modified files
        for path in changed:
            item = QTreeWidgetItem()
            item.setText(0, "Modified")
            item.setText(1, path)
            item.setText(2, self.old_hashes.get(path, ""))
            item.setText(3, self.new_hashes.get(path, ""))
            item.setForeground(0, QColor("#FFA500"))  # Orange
            self.results_tree.addTopLevelItem(item)
        
        # Add new files
        for path in new_files:
            item = QTreeWidgetItem()
            item.setText(0, "New")
            item.setText(1, path)
            item.setText(2, "N/A")
            item.setText(3, self.new_hashes.get(path, ""))
            item.setForeground(0, QColor("#4EC9B0"))  # Teal
            self.results_tree.addTopLevelItem(item)
        
        # Add deleted files
        for path in deleted_files:
            item = QTreeWidgetItem()
            item.setText(0, "Deleted")
            item.setText(1, path)
            item.setText(2, self.old_hashes.get(path, ""))
            item.setText(3, "N/A")
            item.setForeground(0, QColor("#F44747"))  # Red
            self.results_tree.addTopLevelItem(item)
        
        # Sort by status
        self.results_tree.sortItems(0, Qt.AscendingOrder)
        
        # Add summary item
        if changed or new_files or deleted_files:
            summary = QTreeWidgetItem()
            summary.setText(0, "Summary")
            summary.setText(1, f"{len(changed)} modified, {len(new_files)} new, {len(deleted_files)} deleted")
            summary.setFont(0, QFont("Segoe UI", 9, QFont.Bold))
            summary.setFont(1, QFont("Segoe UI", 9, QFont.Bold))
            summary.setBackground(0, QColor("#3D3D40"))
            summary.setBackground(1, QColor("#3D3D40"))
            summary.setBackground(2, QColor("#3D3D40"))
            summary.setBackground(3, QColor("#3D3D40"))
            self.results_tree.addTopLevelItem(summary)
        else:
            item = QTreeWidgetItem()
            item.setText(0, "No changes")
            item.setText(1, "All files are intact")
            item.setForeground(0, QColor("#57A64A"))  # Green
            self.results_tree.addTopLevelItem(item)

if __name__ == "__main__":
    app = QApplication([])
    app.setStyle("Fusion")  # Use Fusion style for better appearance
    
    # Set application icon (optional)
    # app.setWindowIcon(QIcon("icon.png"))
    
    window = FileIntegrityGUI()
    window.show()
    app.exec_()