import requests
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
                           QPushButton, QHeaderView, QHBoxLayout, QLabel,
                           QMessageBox, QLineEdit, QDialog, QFormLayout)
from PyQt5.QtCore import Qt, QTimer

class CommandsWidget(QWidget):
    def __init__(self, auth, board_id=None, parent=None):
        super().__init__(parent)
        self.auth = auth
        self.board_id = board_id
        self.setup_ui()
        
        # Set up refresh timer (10 seconds)
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_commands)
        self.refresh_timer.start(10000)  # 10 seconds
        
    def setup_ui(self):
        self.layout = QVBoxLayout()
        
        # Header with board ID, status and refresh button
        header_layout = QHBoxLayout()
        self.board_label = QLabel("Board: " + (self.board_id or "No board selected"))
        self.board_label.setStyleSheet("font-weight: bold; font-size: 16px;")
        
        self.status_label = QLabel("Commands")
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_commands)
        
        header_layout.addWidget(self.board_label)
        header_layout.addWidget(self.status_label)
        header_layout.addStretch()
        header_layout.addWidget(self.refresh_button)
        
        # Command actions
        actions_layout = QHBoxLayout()
        
        self.add_command_button = QPushButton("Add Command")
        self.add_command_button.clicked.connect(self.on_add_command)
        
        self.remove_command_button = QPushButton("Remove Command")
        self.remove_command_button.clicked.connect(self.on_remove_command)
        
        self.back_button = QPushButton("Back to Boards")
        self.back_button.clicked.connect(self.on_back_button)
        
        actions_layout.addWidget(self.add_command_button)
        actions_layout.addWidget(self.remove_command_button)
        actions_layout.addStretch()
        actions_layout.addWidget(self.back_button)
        
        # Table to show commands
        self.commands_table = QTableWidget()
        self.commands_table.setColumnCount(2)
        self.commands_table.setHorizontalHeaderLabels(["ID", "Command"])
        self.commands_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.commands_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        self.layout.addLayout(header_layout)
        self.layout.addLayout(actions_layout)
        self.layout.addWidget(self.commands_table)
        
        self.setLayout(self.layout)
        
        # Initial load of commands if board_id is provided
        if self.board_id:
            self.refresh_commands()
            
    def set_board_id(self, board_id):
        """Set or change the current board ID"""
        self.board_id = board_id
        self.board_label.setText("Board: " + (self.board_id or "No board selected"))
        self.refresh_commands()
        
    def refresh_commands(self):
        """Fetch and display commands for the current board"""
        if not self.board_id:
            return
            
        try:
            session = self.auth.get_session()
            response = session.get(f"{self.auth.base_url}/get_all_commands?esp_id={self.board_id}")
            
            if response.status_code == 200:
                commands = response.json().get("commands", [])
                self.display_commands(commands)
                self.status_label.setText(f"Commands ({len(commands)})")
            elif response.status_code == 401:
                # Session expired - try to refresh automatically
                self.status_label.setText("Refreshing session...")
                if self.auth.refresh_session():
                    # Successfully refreshed, try the request again
                    self.refresh_commands()
                else:
                    # Unable to refresh automatically, show login dialog immediately
                    self.status_label.setText("Session expired")
                    QMessageBox.information(self, "Session Expired", 
                                     "Your session has expired. Please log in again.")
                    self.parent().show_login()
            else:
                self.status_label.setText("Failed to fetch commands")
        except requests.RequestException as e:
            self.status_label.setText(f"Connection error: {str(e)[:30]}...")
    
    def display_commands(self, commands):
        """Display commands in the table"""
        self.commands_table.setRowCount(len(commands))
        
        for row, command in enumerate(commands):
            # Command ID
            id_item = QTableWidgetItem(str(command.get("id", "")))
            id_item.setFlags(id_item.flags() & ~Qt.ItemIsEditable)
            self.commands_table.setItem(row, 0, id_item)
            
            # Command text
            cmd_item = QTableWidgetItem(command.get("command", ""))
            cmd_item.setFlags(cmd_item.flags() & ~Qt.ItemIsEditable)
            self.commands_table.setItem(row, 1, cmd_item)
    
    def on_add_command(self):
        """Show dialog to add a new command"""
        if not self.board_id:
            QMessageBox.warning(self, "Error", "No board selected")
            return
            
        dialog = AddCommandDialog(self.board_id, self)
        if dialog.exec_() == QDialog.Accepted:
            self.refresh_commands()
    
    def on_remove_command(self):
        """Remove the selected command"""
        selected_items = self.commands_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Error", "No command selected")
            return
            
        row = selected_items[0].row()
        command_id = self.commands_table.item(row, 0).text()
        
        reply = QMessageBox.question(self, "Confirm Delete", 
                                 f"Are you sure you want to delete command {command_id}?",
                                 QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            try:
                session = self.auth.get_session()
                response = session.post(
                    f"{self.auth.base_url}/remove_command",
                    data={"command_id": command_id}
                )
                
                if response.status_code == 200:
                    QMessageBox.information(self, "Success", "Command removed successfully")
                    self.refresh_commands()
                elif response.status_code == 401:
                    # Session expired - try to refresh automatically
                    if self.auth.refresh_session():
                        # Try the operation again
                        self.on_remove_command()
                    else:
                        # Show login dialog
                        QMessageBox.information(self, "Session Expired", 
                                         "Your session has expired. Please log in again.")
                        self.parent().show_login()
                else:
                    QMessageBox.warning(self, "Error", 
                                    f"Failed to remove command: {response.json().get('message', 'Unknown error')}")
            except requests.RequestException as e:
                QMessageBox.warning(self, "Connection Error", str(e))
    
    def on_back_button(self):
        """Go back to the boards list"""
        self.parent().show_boards()
        
    def stop_timer(self):
        """Stop the refresh timer when widget is not active"""
        if self.refresh_timer.isActive():
            self.refresh_timer.stop()
    
    def start_timer(self):
        """Start the refresh timer when widget becomes active"""
        if not self.refresh_timer.isActive():
            self.refresh_timer.start(10000)


class AddCommandDialog(QDialog):
    def __init__(self, board_id, parent=None):
        super().__init__(parent)
        self.board_id = board_id
        self.parent = parent
        self.setup_ui()
        
    def setup_ui(self):
        self.setWindowTitle(f"Add Command to Board {self.board_id}")
        self.setMinimumWidth(400)
        
        layout = QVBoxLayout()
        
        form_layout = QFormLayout()
        
        self.command_input = QLineEdit()
        form_layout.addRow("Command:", self.command_input)
        
        button_layout = QHBoxLayout()
        
        self.add_button = QPushButton("Add")
        self.add_button.clicked.connect(self.on_add)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.add_button)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(form_layout)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def on_add(self):
        """Add the command to the board"""
        command = self.command_input.text().strip()
        
        if not command:
            QMessageBox.warning(self, "Error", "Command cannot be empty")
            return
            
        try:
            session = self.parent.auth.get_session()
            response = session.post(
                f"{self.parent.auth.base_url}/command",
                data={
                    "esp_id": self.board_id,
                    "command": command
                }
            )
            
            if response.status_code == 200:
                QMessageBox.information(self, "Success", "Command added successfully")
                self.accept()
            elif response.status_code == 401:
                # Session expired - try to refresh automatically
                if self.parent.auth.refresh_session():
                    # Try the operation again
                    self.on_add()
                else:
                    # Show login dialog
                    QMessageBox.information(self, "Session Expired", 
                                     "Your session has expired. Please log in again.")
                    self.parent().parent().show_login()
                    self.reject()
            else:
                QMessageBox.warning(self, "Error", 
                                 f"Failed to add command: {response.json().get('message', 'Unknown error')}")
        except requests.RequestException as e:
            QMessageBox.warning(self, "Connection Error", str(e))