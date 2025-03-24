import requests
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
                           QPushButton, QHeaderView, QHBoxLayout, QLabel,
                           QMessageBox)
from PyQt5.QtCore import Qt, QTimer

class BoardsWidget(QWidget):
    def __init__(self, auth, parent=None):
        super().__init__(parent)
        self.auth = auth
        self.setup_ui()
        
        # Set up auto-refresh timer (15 seconds)
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_boards)
        self.refresh_timer.start(15000)  # 15 seconds
        
    def setup_ui(self):
        self.layout = QVBoxLayout()
        
        # Header with status and refresh button
        header_layout = QHBoxLayout()
        self.status_label = QLabel("Active Boards")
        self.status_label.setStyleSheet("font-weight: bold; font-size: 16px;")
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_boards)
        
        header_layout.addWidget(self.status_label)
        header_layout.addStretch()
        header_layout.addWidget(self.refresh_button)
        
        # Table to show active boards
        self.boards_table = QTableWidget()
        self.boards_table.setColumnCount(2)
        self.boards_table.setHorizontalHeaderLabels(["Board ID", "Last Activity"])
        self.boards_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.boards_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        # Connect double-click event to view board details
        self.boards_table.cellDoubleClicked.connect(self.on_board_double_clicked)
        
        self.layout.addLayout(header_layout)
        self.layout.addWidget(self.boards_table)
        
        self.setLayout(self.layout)
        
        # Initial load of boards
        self.refresh_boards()
        
    def refresh_boards(self):
        """Fetch and display active boards"""
        try:
            session = self.auth.get_session()
            response = session.get(f"{self.auth.base_url}/active_boards")
            
            if response.status_code == 200:
                active_boards = response.json().get("active_boards", [])
                self.display_boards(active_boards)
                self.status_label.setText(f"Active Boards ({len(active_boards)})")
            else:
                self.status_label.setText("Failed to fetch boards")
                if response.status_code == 401:
                    QMessageBox.warning(self, "Authentication Error", 
                                     "Your session has expired. Please log in again.")
                    self.parent().show_login()
        except requests.RequestException as e:
            self.status_label.setText(f"Connection error: {str(e)[:30]}...")
    
    def display_boards(self, boards):
        """Display boards in the table"""
        self.boards_table.setRowCount(len(boards))
        
        for row, board in enumerate(boards):
            # Board ID
            id_item = QTableWidgetItem(board.get("esp_id", "Unknown"))
            id_item.setFlags(id_item.flags() & ~Qt.ItemIsEditable)
            self.boards_table.setItem(row, 0, id_item)
            
            # Last activity
            last_activity = board.get("last_request_duration", "Unknown")
            activity_item = QTableWidgetItem(last_activity)
            activity_item.setFlags(activity_item.flags() & ~Qt.ItemIsEditable)
            self.boards_table.setItem(row, 1, activity_item)
    
    def on_board_double_clicked(self, row, column):
        """Handle double click on a board - emit signal for parent to show board details"""
        board_id = self.boards_table.item(row, 0).text()
        self.parent().show_board_commands(board_id)
        
    def stop_timer(self):
        """Stop the refresh timer when widget is not active"""
        if self.refresh_timer.isActive():
            self.refresh_timer.stop()
    
    def start_timer(self):
        """Start the refresh timer when widget becomes active"""
        if not self.refresh_timer.isActive():
            self.refresh_timer.start(15000)
    
    def get_selected_board(self):
        """Return the currently selected board ID"""
        selected_items = self.boards_table.selectedItems()
        if selected_items:
            row = selected_items[0].row()
            return self.boards_table.item(row, 0).text()
        return None