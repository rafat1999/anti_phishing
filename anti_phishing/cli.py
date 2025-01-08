import asyncio
import nest_asyncio
from .core import FirebaseAntiPhishing
from .database import DatabaseManager
from .utils import print_banner
import os

async def main_loop(system: FirebaseAntiPhishing) -> None:
    """Main application loop"""
    while True:
        print("\n=== Student Anti-Phishing System ===")
        student_id = input("Enter student ID (or 'quit' to exit): ")
        if student_id.lower() == 'quit':
            break
        password = input("Enter password: ")
        success, message = await system.login(student_id, password)
        print(f"\n{message}")
        
        if success:
            while True:
                print("\n1. Check URL")
                print("2. View My Check History")
                print("3. Logout")
                choice = input("Enter your choice (1-3): ")
                
                if choice == '3':
                    system.current_user = None
                    break
                elif choice == '1':
                    url = input("\nEnter URL to check: ")
                    safe, message = await system.check_url(url)
                    print(f"\n{message}")
                elif choice == '2':
                    logs = await system.get_student_logs(student_id)
                    print("\nYour URL Check History:")
                    for log in logs:
                        print(f"\nTime: {log['timestamp']}")
                        print(f"URL: {log['url_checked']}")
                        print(f"Status: {log['status']}")
                else:
                    print("\nInvalid choice!")

def main():
    """Entry point for the application"""
    nest_asyncio.apply()
    print_banner()
    
    # Try to connect to Firebase using environment variable
    cred_path = os.getenv('FIREBASE_CREDENTIALS')
    if cred_path and os.path.exists(cred_path):
        db_manager = DatabaseManager(cred_path)
        system = FirebaseAntiPhishing(db_manager)
        print("\nConnected to Firebase database")
    else:
        system = FirebaseAntiPhishing()
        print("\nRunning in Demo Mode")
        print("Use these credentials to login:")
        print("Student ID: DEMO001")
        print("Password: demo123")
    
    try:
        asyncio.run(main_loop(system))
    except KeyboardInterrupt:
        print("\nGoodbye!")
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")

if __name__ == "__main__":
    main()
