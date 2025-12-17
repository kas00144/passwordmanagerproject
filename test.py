import unittest
import json
import os
import io
from unittest.mock import patch
from main import (
    is_strong_password,
    generate_password,
    add_password,
    get_password,
    save_passwords,
    load_passwords,
    websites,
    usernames,
    encrypted_passwords,
    caesar_encrypt,
    caesar_decrypt,
    SHIFT,
)

class TestPasswordManager(unittest.TestCase):

    def setUp(self):
        # Clear global lists before each test
        websites.clear()
        usernames.clear()
        encrypted_passwords.clear()
        # Remove vault.txt if it exists
        if os.path.exists("vault.txt"):
            os.remove("vault.txt")

    def tearDown(self):
        # Clean up vault.txt after each test
        if os.path.exists("vault.txt"):
            os.remove("vault.txt")

    def test_is_strong_password(self):
        self.assertTrue(is_strong_password("Str0ngP@ssw0rd"))
        self.assertFalse(is_strong_password("Weak123"))
        self.assertFalse(is_strong_password("weakpassword123!"))
        self.assertFalse(is_strong_password("Weakpassword123"))

    def test_generate_password(self):
        pw12 = generate_password(12)
        self.assertEqual(len(pw12), 12)
        self.assertTrue(is_strong_password(pw12))

        pw16 = generate_password(16)
        self.assertEqual(len(pw16), 16)
        self.assertTrue(is_strong_password(pw16))

    @patch("builtins.input", side_effect=["example.com", "user123", "n", "Str0ngP@ssw0rd"])
    def test_add_password(self, mock_input):
        add_password()
        self.assertIn("example.com", websites)
        idx = websites.index("example.com")
        self.assertEqual(usernames[idx], "user123")
        self.assertEqual(caesar_decrypt(encrypted_passwords[idx], SHIFT), "Str0ngP@ssw0rd")

    @patch("builtins.input", side_effect=["example.com"])
    def test_get_password(self, mock_input):
        # Preload a password
        websites.append("example.com")
        usernames.append("user123")
        encrypted_passwords.append(caesar_encrypt("Str0ngP@ssw0rd", SHIFT))

        with patch("sys.stdout", new_callable=io.StringIO) as fake_out:
            get_password()
            output = fake_out.getvalue()
            self.assertIn("Website: example.com", output)
            self.assertIn("Username: user123", output)
            self.assertIn("Str0ngP@ssw0rd", output)

    def test_save_and_load_passwords(self):
        # Preload a password
        websites.append("example.com")
        usernames.append("user123")
        encrypted_passwords.append(caesar_encrypt("Str0ngP@ssw0rd", SHIFT))

        save_passwords()
        self.assertTrue(os.path.exists("vault.txt"))

        # Clear lists and reload
        websites.clear()
        usernames.clear()
        encrypted_passwords.clear()
        data = load_passwords()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["website"], "example.com")
        self.assertEqual(data[0]["username"], "user123")
        self.assertEqual(caesar_decrypt(data[0]["password"], SHIFT), "Str0ngP@ssw0rd")


if __name__ == "__main__":
    unittest.main()
