import hashlib
import os

def generate_salt():
    # Generate a random 16-byte salt using os.urandom
    return os.urandom(16)

def hash_password(password, salt):
    # Concatenate the password and salt
    salted_password = password + salt
    # Hash the salted password using SHA-256
    hashed_password = hashlib.sha256(salted_password).digest()
    return hashed_password

def verify_password(hashed_password, salt, password):
    # Hash the provided password with the salt
    new_hashed_password = hash_password(password, salt)
    # Compare the new hash with the original hash
    return new_hashed_password == hashed_password

# Example usage
if __name__ == "__main__":
    # Prompt the user to enter a password
    password = input("Enter your password: ")

    # Generate a salt
    salt = generate_salt()

    # Hash the password with the salt
    hashed_password = hash_password(password.encode('utf-8'), salt)
    print("Hashed password:", hashed_password)

    # Prompt the user to re-enter the password for verification
    verify_password_input = input("Enter your password again for verification: ")

    # Verify the password
    if verify_password(hashed_password, salt, verify_password_input.encode('utf-8')):
        print("Password verified!")
    else:
        print("Password verification failed.")
