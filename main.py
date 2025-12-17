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
    if password is None:
        return False
    if len(password) < 12:
        return False
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    if not (has_lower and has_upper and has_digit and has_special):
        return False
    weak_patterns = ["password", "passw0rd", "qwerty", "123456", "123456789", "abc123", "letmein", "iloveyou", "admin"]
    lower_pw = password.lower()
    if any(pat in lower_pw for pat in weak_patterns):
        return False
    if re.fullmatch(r'(.)\1{7,}', password):
        return False
    return True

# Password generator function (optional)
def generate_password(length):
    """
    Generate a random strong password of the specified length.

    Args:
        length (int): The desired length of the password.

    Returns:
        str: A random strong password.
    """
    if not isinstance(length, int) or length < 12:
        length = 12
    rng = random.SystemRandom()
    lowers = string.ascii_lowercase
    uppers = string.ascii_uppercase
    digits = string.digits
    specials = string.punctuation

    required = [
        rng.choice(lowers),
        rng.choice(uppers),
        rng.choice(digits),
        rng.choice(specials),
    ]

    all_chars = lowers + uppers + digits + specials
    remaining = [rng.choice(all_chars) for _ in range(length - len(required))]
    password_chars = required + remaining
    rng.shuffle(password_chars)

    return "".join(password_chars)


# Initialize empty lists to store encrypted passwords, websites, and usernames
encrypted_passwords = []
websites = []
usernames = []

SHIFT = 3

# Function to add a new password 
def add_password():
    """
    Add a new password to the password manager.

    This function should prompt the user for the website, username,  and password and store them to lists with same index. Optionally, it should check password strengh with the function is_strong_password. It may also include an option for the user to
    generate a random strong password by calling the generate_password function.

    Returns:
        None
    """
    site = input("Enter website (e.g., example.com): ").strip()
    if not site:
        print("Website cannot be empty.")
        return
    
    user = input("Enter username: ").strip()
    if not user:
        print("Username cannot be empty.")
        return
    
    use_generator = input("Generate a random strong password? (y/n): ").strip().lower()
    if use_generator == "y":
        try:
            desired_len = int(input("Desired password length (min 12): ").strip())
        except ValueError:
            print("Invalid length. Using default 12.")
            desired_len = 12
        password = generate_password(desired_len)
        print("Generated password:", password)
    else:
        password = input("Enter password: ")

    if not is_strong_password(password):
        print("WARNING: This password does not meet strong password criteria.")
        return

    enc = caesar_encrypt(password, SHIFT)

    if site in websites:
        idx = websites.index(site)
        websites[idx] = site
        usernames[idx] = user
        encrypted_passwords[idx] = enc
        print(f"Updated credentials for {site}.")
    else:
        websites.append(site)
        usernames.append(user)
        encrypted_passwords.append(enc)
        print(f"Added credentials for {site}.")

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
    file named "vault.txt" in a structured format (JSON).

    Returns:
        None
    """
    data = []
    for i in range(len(websites)):
        entry = {
            "website": websites[i],
            "username": usernames[i],
            "password": encrypted_passwords[i],  # Caesar-salattu merkkijono
        }
        data.append(entry)

    try:
        with open("vault.txt", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print("Passwords saved to vault.txt.")
    except Exception as e:
        print(f"Error saving passwords: {e}")



def load_passwords():
    try:
        with open("vault.txt", "r", encoding="utf-8") as f:
            data = json.load(f)
        websites.clear()
        usernames.clear()
        encrypted_passwords.clear()
        for entry in data:
            site = entry.get("website", "").strip()
            user = entry.get("username", "").strip()
            enc = entry.get("password", "")
            if not site or not user or not isinstance(enc, str):
                continue
            websites.append(site)
            usernames.append(user)
            encrypted_passwords.append(enc)
        return data
    except FileNotFoundError:
        print("vault.txt not found. Nothing loaded.")
        return []
    except json.JSONDecodeError as e:
        print(f"Error decoding vault.txt (is it valid JSON?): {e}")
        return []
    except Exception as e:
        print(f"Unexpected error loading passwords: {e}")
        return []
def main(): 
    

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
        load_passwords()
    elif choice == "5":
        break
    else:
        print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
