import sqlite3

# This file contains vulnerabilities to be caught by VibeSentinel

def connect_db():
    # Hardcoded secret
    API_KEY = "sk-live-abcdef1234567890"
    db_password = "super_secret_password!"
    
    conn = sqlite3.connect("users.db")
    return conn

def get_user_data(user_id):
    conn = connect_db()
    cursor = conn.cursor()
    
    # Needs Row Level Security and has Command Injection (Input Sanitization flaw)
    query = f"SELECT * FROM accounts WHERE id = {user_id}"
    
    cursor.execute(query)
    data = cursor.fetchall()
    
    return data

def process_payment(amount, user_id):
    # Domain specific problem: No check if user is verified
    print(f"Processing ${amount} for User: {user_id}")
    return True
