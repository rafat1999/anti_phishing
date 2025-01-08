import hashlib
import re
import urllib.parse
from datetime import datetime, timedelta
from typing import Tuple, Optional, Dict, Any

from .database import DatabaseManager
from .utils import normalize_url, check_suspicious_patterns

class FirebaseAntiPhishing:
    def __init__(self, database_manager: Optional[DatabaseManager] = None):
        """Initialize the anti-phishing system"""
        self.db = database_manager
        self.current_user = None
        self.max_login_attempts = 3

    async def login(self, student_id: str, password: str) -> Tuple[bool, str]:
        """Authenticate student and manage login attempts"""
        if not self.db:
            return False, "System is in demo mode - no database connection"

        try:
            student_data = await self.db.get_student(student_id)
            if not student_data:
                return False, "Invalid student ID"

            if student_data.get('account_locked'):
                return False, "Account is locked. Please contact administrator."

            password_hash = hashlib.sha256(password.encode()).hexdigest()

            if student_data['password_hash'] == password_hash:
                await self.db.update_login_success(student_id)
                self.current_user = student_data
                return True, "Login successful"

            # Handle failed login
            result = await self.db.update_login_failure(student_id, self.max_login_attempts)
            return False, result

        except Exception as e:
            return False, f"An error occurred during login: {str(e)}"

    async def check_url(self, url: str) -> Tuple[Optional[bool], str]:
        """Check if URL is potentially malicious"""
        if not self.current_user:
            return None, "No authenticated user"

        try:
            normalized_url = normalize_url(url)
            
            # Check against known phishing URLs if database is available
            if self.db:
                phishing_match = await self.db.check_known_phishing_url(normalized_url)
                if phishing_match:
                    await self.log_check(url, f"Malicious - {phishing_match}")
                    return False, f"Warning: Known phishing URL detected! {phishing_match}"

            # Check suspicious patterns
            suspicious = check_suspicious_patterns(normalized_url)
            if suspicious:
                await self.log_check(url, f"Suspicious - {suspicious}")
                return False, f"Warning: {suspicious} detected! Exercise caution!"

            await self.log_check(url, "Safe")
            return True, "URL appears to be safe"

        except Exception as e:
            return None, f"An error occurred while checking the URL: {str(e)}"

    async def log_check(self, url: str, status: str) -> None:
        """Log URL check attempts"""
        if self.db and self.current_user:
            await self.db.log_url_check(
                self.current_user['student_id'],
                f"{self.current_user['first_name']} {self.current_user['last_name']}",
                url,
                status
            )

    async def get_student_logs(self, student_id: str) -> list:
        """Retrieve URL check logs for a specific student"""
        if not self.db:
            return []
        return await self.db.get_student_logs(student_id)
