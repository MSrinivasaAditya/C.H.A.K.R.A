import sqlite3
import os
import pickle
import hashlib
import random

# Vulnerability 1: Hardcoded Secret
AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
API_TOKEN = "xyz123_super_secret_token"

def check_user_login(username, password):
    """""
    Vulnerability 2: SQL Injection
    Constructs a SQL query using string interpolation (f-strings) instead of parameterized queries.
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()

def ping_host(ip_address):
    """
    Vulnerability 3: Command Injection
    Appends untrusted user input directly to a system command.
    """
    command = "ping -c 4 " + ip_address
    os.system(command)

def load_session(serialized_data):
    """
    Vulnerability 4: Pickle Deserialization
    Unpickling untrusted data can lead to arbitrary code execution.
    """
    return pickle.loads(serialized_data)

def hash_password(password):
    """
    Vulnerability 5: MD5 Weak Hash
    Uses the cryptographically broken MD5 hashing algorithm.
    """
    hasher = hashlib.md5()
    hasher.update(password.encode('utf-8'))
    return hasher.hexdigest()

def generate_password_reset_token():
    """
    Vulnerability 6: Insecure Random
    The standard `random` module is not cryptographically secure and predictable.
    """
    return str(random.randint(100000, 999999))

def compute_expression(expression):
    """
    Vulnerability 7: Eval Code Injection
    Allows execution of arbitrary Python code if the expression is untrusted.
    """
    return eval(expression)

if __name__ == "__main__":
    print("Welcome to the CHAKRA Demo Vulnerable Application.")
    # This file serves purely as a test target for Semgrep and CHAKRA pipeline.
