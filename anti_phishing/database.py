from typing import Optional, Dict, Any
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime

class DatabaseManager:
    def __init__(self, credential_path: str):
        """Initialize Firebase connection"""
        try:
            firebase_admin.get_app()
        except ValueError:
            cred = credentials.Certificate(credential_path)
            firebase_admin.initialize_app(cred)
        
        self.db = firestore.client()

    async def get_student(self, student_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve student data"""
        doc = self.db.collection('students').document(student_id).get()
        return doc.to_dict() if doc.exists else None

    async def update_login_success(self, student_id: str) -> None:
        """Update successful login information"""
        self.db.collection('students').document(student_id).update({
            'last_login': datetime.now(),
            'failed_login_attempts': 0
        })

    async def update_login_failure(self, student_id: str, max_attempts: int) -> str:
        """Update failed login attempts"""
        doc_ref = self.db.collection('students').document(student_id)
        doc = doc_ref.get()
        data = doc.to_dict()
        
        failed_attempts = data['failed_login_attempts'] + 1
        updates = {'failed_login_attempts': failed_attempts}

        if failed_attempts >= max_attempts:
            updates['account_locked'] = True
            doc_ref.update(updates)
            return "Account locked due to too many failed attempts"

        doc_ref.update(updates)
        return f"Invalid credentials. {max_attempts - failed_attempts} attempts remaining"

    async def check_known_phishing_url(self, normalized_url: str) -> Optional[str]:
        """Check if URL matches known phishing URLs"""
        phishing_urls = self.db.collection('phishing_urls').stream()
        for doc in phishing_urls:
            data = doc.to_dict()
            if data['url'].lower() in normalized_url:
                return f"Threat Level: {data['threat_level']}"
        return None

    async def log_url_check(self, student_id: str, student_name: str, 
                           url: str, status: str) -> None:
        """Log URL check attempt"""
        self.db.collection('url_check_logs').add({
            'timestamp': datetime.now(),
            'student_id': student_id,
            'student_name': student_name,
            'url_checked': url,
            'status': status
        })

    async def get_student_logs(self, student_id: str) -> list:
        """Retrieve URL check logs for a student"""
        logs = self.db.collection('url_check_logs')\
            .where('student_id', '==', student_id)\
            .order_by('timestamp', direction=firestore.Query.DESCENDING)\
            .stream()
        return [log.to_dict() for log in logs]
