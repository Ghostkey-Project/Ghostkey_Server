import requests
import os
from requests.auth import HTTPBasicAuth
from PyQt5.QtWidgets import (QDialog, QLabel, QLineEdit, 
                            QPushButton, QVBoxLayout, QHBoxLayout,
                            QMessageBox, QCheckBox)

class Authentication:
    def __init__(self, base_url):
        self.base_url = base_url
        self.username = None
        self.password = None
        self.session = requests.Session()
        self.auth_method = "session"  # "session" or "basic"
        
        # Try to load credentials from file
        self.load_credentials()
        
    def login(self, username, password):
        """Login with username and password using session authentication"""
        self.username = username
        self.password = password
        
        try:
            if self.auth_method == "session":
                # Session-based authentication
                response = self.session.post(
                    f"{self.base_url}/login",
                    data={"username": username, "password": password}
                )
            else:
                # Basic authentication
                self.session.auth = HTTPBasicAuth(username, password)
                response = self.session.get(f"{self.base_url}/active_boards")
                
            if response.status_code == 200:
                return True, "Login successful"
            else:
                return False, f"Login failed: {response.json().get('message', 'Unknown error')}"
        except requests.RequestException as e:
            return False, f"Connection error: {str(e)}"
    
    def refresh_session(self):
        """Attempt to refresh an expired session"""
        if not self.username or not self.password:
            return False
            
        try:
            # Re-authenticate with stored credentials
            if self.auth_method == "session":
                # For session auth, we need to login again
                response = self.session.post(
                    f"{self.base_url}/login",
                    data={"username": self.username, "password": self.password}
                )
            else:
                # For basic auth, just update the auth header
                self.session.auth = HTTPBasicAuth(self.username, self.password)
                response = self.session.get(f"{self.base_url}/active_boards")
                
            return response.status_code == 200
        except:
            return False
            
    def logout(self):
        """Logout from the server"""
        if self.auth_method == "session":
            try:
                response = self.session.post(f"{self.base_url}/logout")
                if response.status_code == 200:
                    self.session = requests.Session()
                    return True, "Logout successful"
                else:
                    return False, f"Logout failed: {response.json().get('message', 'Unknown error')}"
            except requests.RequestException as e:
                return False, f"Connection error: {str(e)}"
        else:
            # For basic auth, just reset the session
            self.session = requests.Session()
            return True, "Logged out"
    
    def save_credentials(self, remember=False):
        """Save credentials to file if remember is True"""
        if remember and self.username and self.password:
            with open(".credentials", "w") as f:
                f.write(f"{self.username}\n{self.password}\n{self.auth_method}")
        else:
            # Remove the credentials file if it exists
            if os.path.exists(".credentials"):
                os.remove(".credentials")
    
    def load_credentials(self):
        """Load credentials from file if it exists"""
        if os.path.exists(".credentials"):
            try:
                with open(".credentials", "r") as f:
                    lines = f.readlines()
                    if len(lines) >= 3:
                        self.username = lines[0].strip()
                        self.password = lines[1].strip()
                        self.auth_method = lines[2].strip()
                        return True
            except Exception:
                pass
        return False

    def is_authenticated(self):
        """Check if user is authenticated"""
        if not self.username or not self.password:
            return False
            
        try:
            # Try to access a protected endpoint
            if self.auth_method == "session":
                response = self.session.get(f"{self.base_url}/active_boards")
            else:
                response = self.session.get(
                    f"{self.base_url}/active_boards", 
                    auth=HTTPBasicAuth(self.username, self.password)
                )
            return response.status_code == 200
        except:
            return False
            
    def set_auth_method(self, method):
        """Set authentication method (session or basic)"""
        if method in ["session", "basic"]:
            self.auth_method = method
            
    def get_auth_method(self):
        """Get current authentication method"""
        return self.auth_method
        
    def get_session(self):
        """Get the current session object"""
        if self.auth_method == "basic" and self.username and self.password:
            # For basic auth, make sure auth is set
            self.session.auth = HTTPBasicAuth(self.username, self.password)
        return self.session


class LoginDialog(QDialog):
    def __init__(self, auth, parent=None):
        super().__init__(parent)
        self.auth = auth
        self.setup_ui()
        
    def setup_ui(self):
        self.setWindowTitle("Login to Ghostkey Server")
        self.setMinimumWidth(300)
        
        # Create widgets
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        if self.auth.username:
            self.username_input.setText(self.auth.username)
        
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        if self.auth.password:
            self.password_input.setText(self.auth.password)
            
        # Authentication method
        self.auth_method_label = QLabel("Authentication Method:")
        self.session_auth_checkbox = QCheckBox("Session Authentication")
        self.basic_auth_checkbox = QCheckBox("Basic Authentication")
        
        if self.auth.get_auth_method() == "session":
            self.session_auth_checkbox.setChecked(True)
        else:
            self.basic_auth_checkbox.setChecked(True)
            
        # Connect events
        self.session_auth_checkbox.clicked.connect(self.on_session_auth_clicked)
        self.basic_auth_checkbox.clicked.connect(self.on_basic_auth_clicked)
        
        self.remember_checkbox = QCheckBox("Remember credentials")
        
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.on_login)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        # Create layouts
        main_layout = QVBoxLayout()
        
        form_layout = QVBoxLayout()
        form_layout.addWidget(self.username_label)
        form_layout.addWidget(self.username_input)
        form_layout.addWidget(self.password_label)
        form_layout.addWidget(self.password_input)
        form_layout.addWidget(self.auth_method_label)
        
        auth_layout = QHBoxLayout()
        auth_layout.addWidget(self.session_auth_checkbox)
        auth_layout.addWidget(self.basic_auth_checkbox)
        form_layout.addLayout(auth_layout)
        
        form_layout.addWidget(self.remember_checkbox)
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.cancel_button)
        
        main_layout.addLayout(form_layout)
        main_layout.addLayout(button_layout)
        
        self.setLayout(main_layout)
        
    def on_session_auth_clicked(self):
        if self.session_auth_checkbox.isChecked():
            self.basic_auth_checkbox.setChecked(False)
            self.auth.set_auth_method("session")
        else:
            self.basic_auth_checkbox.setChecked(True)
            self.auth.set_auth_method("basic")
    
    def on_basic_auth_clicked(self):
        if self.basic_auth_checkbox.isChecked():
            self.session_auth_checkbox.setChecked(False)
            self.auth.set_auth_method("basic")
        else:
            self.session_auth_checkbox.setChecked(True)
            self.auth.set_auth_method("session")
    
    def on_login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Login Error", "Username and password are required")
            return
        
        success, message = self.auth.login(username, password)
        if success:
            # Save credentials if remember is checked
            self.auth.save_credentials(self.remember_checkbox.isChecked())
            QMessageBox.information(self, "Login Success", message)
            self.accept()
        else:
            QMessageBox.warning(self, "Login Error", message)