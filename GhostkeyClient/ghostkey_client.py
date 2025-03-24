import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QStackedWidget, 
                           QMessageBox, QInputDialog, QLineEdit)
from PyQt5.QtCore import Qt

from auth import Authentication, LoginDialog
from boards import BoardsWidget
from commands import CommandsWidget

class GhostkeyClient(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Default server URL (configurable)
        self.base_url = "http://localhost:8080"
        
        # Authentication handler
        self.auth = Authentication(self.base_url)
        
        # Initialize UI
        self.setup_ui()
        
    def setup_ui(self):
        self.setWindowTitle("Ghostkey Client")
        self.setMinimumSize(800, 600)
        
        # Create stacked widget for different screens
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)
        
        # Create screens
        self.boards_widget = BoardsWidget(self.auth, self)
        self.commands_widget = CommandsWidget(self.auth, None, self)
        
        # Add widgets to stacked layout
        self.stacked_widget.addWidget(self.boards_widget)
        self.stacked_widget.addWidget(self.commands_widget)
        
        # Start with boards widget
        self.stacked_widget.setCurrentWidget(self.boards_widget)
        
        # Check if we need to show login
        self.check_authentication()
        
    def check_authentication(self):
        """Check if user is authenticated, show login if not"""
        if not self.auth.is_authenticated():
            self.show_login()
            
    def show_login(self):
        """Show login dialog"""
        # Stop all timers
        self.boards_widget.stop_timer()
        self.commands_widget.stop_timer()
        
        login_dialog = LoginDialog(self.auth)
        result = login_dialog.exec_()
        
        if result == login_dialog.Accepted:
            # Show boards widget
            self.show_boards()
        else:
            # Exit if login canceled and no prior authentication
            if not self.auth.is_authenticated():
                sys.exit()
                
    def show_boards(self):
        """Switch to boards view"""
        # Stop command widget timer
        self.commands_widget.stop_timer()
        
        # Start boards widget timer
        self.boards_widget.start_timer()
        self.boards_widget.refresh_boards()
        
        # Switch to boards widget
        self.stacked_widget.setCurrentWidget(self.boards_widget)
        
    def show_board_commands(self, board_id):
        """Switch to commands view for a specific board"""
        # Stop boards widget timer
        self.boards_widget.stop_timer()
        
        # Set board ID and start commands widget timer
        self.commands_widget.set_board_id(board_id)
        self.commands_widget.start_timer()
        
        # Switch to commands widget
        self.stacked_widget.setCurrentWidget(self.commands_widget)
        
    def configure_server(self):
        """Allow user to change server URL"""
        url, ok = QInputDialog.getText(
            self, 
            "Configure Server", 
            "Enter server URL:", 
            QLineEdit.Normal, 
            self.base_url
        )
        
        if ok and url:
            self.base_url = url
            self.auth.base_url = url
            QMessageBox.information(self, "Server Changed", f"Server URL changed to {url}")
            
            # Refresh after changing server
            self.check_authentication()
        
    def closeEvent(self, event):
        """Handle window close event"""
        # Stop all timers
        self.boards_widget.stop_timer()
        self.commands_widget.stop_timer()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = GhostkeyClient()
    window.show()
    sys.exit(app.exec_())