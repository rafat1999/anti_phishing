import os
from typing import Optional, Dict, Any
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime
import logging

class DatabaseManager:
    _instance = None  # Singleton instance

    @staticmethod
    def auto_connect() -> Optional['DatabaseManager']:
        """Attempt to automatically connect to Firebase using common credential locations"""
        possible_locations = [
            'serviceAccountKey.json',  # Current directory
            '~/serviceAccountKey.json',  # Home directory
            '/etc/anti_phishing/serviceAccountKey.json',  # System directory
            os.getenv('FIREBASE_CREDENTIALS'),  # Environment variable
        ]

        for location in possible_locations:
            if not location:
                continue
                
            try:
                expanded_path = os.path.expanduser(location)
                if os.path.exists(expanded_path):
                    return DatabaseManager(expanded_path)
            except Exception as e:
                logging.warning(f"Failed to connect using {location}: {e}")
                continue
        
        logging.info("No valid Firebase credentials found. Running in demo mode.")
        return None

    def __init__(self, credential_path: str):
        """Initialize Firebase connection"""
        if not os.path.exists(credential_path):
            raise FileNotFoundError(f"Credential file not found: {credential_path}")

        try:
            # Try to get existing app
            firebase_admin.get_app()
        except ValueError:
            # Initialize new app if none exists
            cred = credentials.Certificate(credential_path)
            firebase_admin.initialize_app(cred)
        
        try:
            self.db = firestore.client()
            # Test connection
            self.db.collection('students').limit(1).stream()
        except Exception as e:
            raise ConnectionError(f"Failed to connect to Firestore: {e}")

    async def get_student(self, student_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve student data"""
        try:
            doc = self.db.collection('students').document(student_id).get()
            return doc.to_dict() if doc.exists else None
        except Exception as e:
            logging.error(f"Error retrieving student data: {e}")
            return None

    async def update_login_success(self, student_id: str) -> None:
        """Update successful login information"""
        try:
            self.db.collection('students').document(student_id).update({
                'last_login': datetime.now(),
                'failed_login_attempts': 0
            })
        except Exception as e:
            logging.error(f"Error updating login success: {e}")
            raise

    async def update_login_failure(self, student_id: str, max_attempts: int) -> str:
        """Update failed login attempts"""
        try:
            doc_ref = self.db.collection('students').document(student_id)
            doc = doc_ref.get()
            
            if not doc.exists:
                return "Invalid student ID"
                
            data = doc.to_dict()
            failed_attempts = data.get('failed_login_attempts', 0) + 1
            updates = {'failed_login_attempts': failed_attempts}

            if failed_attempts >= max_attempts:
                updates['account_locked'] = True
                doc_ref.update(updates)
                return "Account locked due to too many failed attempts"

            doc_ref.update(updates)
            return f"Invalid credentials. {max_attempts - failed_attempts} attempts remaining"
        except Exception as e:
            logging.error(f"Error updating login failure: {e}")
            return "An error occurred while processing login"

    async def check_known_phishing_url(self, normalized_url: str) -> Optional[str]:
        """Check if URL matches known phishing URLs"""
        try:
            phishing_urls = self.db.collection('phishing_urls').stream()
            for doc in phishing_urls:
                data = doc.to_dict()
                if data.get('url', '').lower() in normalized_url:
                    return f"Threat Level: {data.get('threat_level', 'Unknown')}"
            return None
        except Exception as e:
            logging.error(f"Error checking phishing URL: {e}")
            return None

    async def log_url_check(self, student_id: str, student_name: str, 
                           url: str, status: str) -> None:
        """Log URL check attempt"""
        try:
            self.db.collection('url_check_logs').add({
                'timestamp': datetime.now(),
                'student_id': student_id,
                'student_name': student_name,
                'url_checked': url,
                'status': status
            })
        except Exception as e:
            logging.error(f"Error logging URL check: {e}")
            # Don't raise the exception as logging failure shouldn't break the application
            pass

    async def get_student_logs(self, student_id: str) -> list:
        """Retrieve URL check logs for a student"""
        try:
            logs = self.db.collection('url_check_logs')\
                .where('student_id', '==', student_id)\
                .order_by('timestamp', direction=firestore.Query.DESCENDING)\
                .stream()
            return [log.to_dict() for log in logs]
        except Exception as e:
            logging.error(f"Error retrieving student logs: {e}")
            return []
