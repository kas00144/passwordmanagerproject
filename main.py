import json
import re
import random
import string

# Caesar cipher encryption and decryption functions (pre-implemented)
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Password strength checker function (optional)
def is_strong_password(password):
    # ...

# Password generator function (optional)
def generate_password(length):
     """
    Generate a random strong password of the specified length.

    Args:
        length (int): The desired length of the password.

    Returns:
        str: A random strong password.
    """

# Initialize empty lists to store encrypted passwords, websites, and usernames
encrypted_passwords = []
websites = []
usernames = []

# Function to add a new password 
def add_password():
    """
    Add a new password to the password manager.

    This function should prompt the user for the website, username,  and password and store them to lits with same index. Optionally, it should check password strengh with the function is_strong_password. It may also include an option for the user to
    generate a random strong password by calling the generate_password function.

    Returns:
        None
    """

# Function to retrieve a password 
def get_password():

    """
    Retrieve a password for a given website.

    This function should prompt the user for the website name and
    then display the username and decrypted password for that website.

    Returns:
        None
    """
    site = input("Enter website to retrieve: ").strip()
    if not site:
        print("Website cannot be empty.")
        return
    if site not in websites:
        print(f"No entry found for '{site}'.")
        return
    idx = websites.index(site)
    user = usernames[idx]
    enc = encrypted_passwords[idx]
    dec = caesar_decrypt(enc, SHIFT)
    print(f"Website: {site}")
    print(f"Username: {user}")
    print(f"Password: {dec}")

# Function to save passwords to a JSON file 
def save_passwords():
 """
    Save the password vault to a file.

    This function should save passwords, websites, and usernames to a text
    file named "vault.txt" in a structured format.

    Returns:
        None
    """

    Returns:
        None
    """

# Function to load passwords from a JSON file 
def load_passwords():
     """
    Load passwords from a file into the password vault.

    This function should load passwords, websites, and usernames from a text
    file named "vault.txt" (or a more generic name) and populate the respective lists.

    Returns:
        None

  # Main method
def main():
# implement user interface 

  while True:
    print("\nPassword Manager Menu:")
    print("1. Add Password")
    print("2. Get Password")
    print("3. Save Passwords")
    print("4. Load Passwords")
    print("5. Quit")
    
    choice = input("Enter your choice: ")
    
    if choice == "1":
        add_password()
    elif choice == "2":
        get_password()
    elif choice == "3":
        save_passwords()
    elif choice == "4":
        passwords = load_passwords()
        print("Passwords loaded successfully!")
    elif choice == "5":
        break
    else:
        print("Invalid choice. Please try again.")

# Execute the main function when the program is run
if __name__ == "__main__":
    main()
