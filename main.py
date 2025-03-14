import getpass
from utilities.module_loader import load_all_modules_from_directory
from credentials.user_auth import register_user, login_user
from credentials.password_manager import add_password, get_password
from credentials.mfa import send_otp_via_email, verify_otp
from utilities.config_encrypt import encrypt_config, decrypt_config
from utilities.logging import log_info, log_warning, log_error
from utilities.report_generator import generate_report

# Load all encryption modules
encryption_modules = load_all_modules_from_directory("cryptography")

def menu():
    print("""
    █████╗ ██████╗ ███████╗███████╗
    ██╔══██╗██╔══██╗██╔════╝██╔════╝
    ███████║██████╔╝███████╗█████╗  
    ██╔══██║██╔═══╝ ╚════██║██╔══╝  
    ██║  ██║██║     ███████║███████╗
    ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝

    [1] Register User
    [2] Login User
    [3] Encrypt Text (AES)
    [4] Decrypt Text (AES)
    [5] Encrypt Data (RSA)
    [6] Decrypt Data (RSA)
    [7] Generate HMAC
    [8] Verify HMAC
    [9] Hash Password (PBKDF2)
    [10] Hash Password (Scrypt)
    [11] Hash Password (Argon2)
    [12] Encrypt Data (DES3)
    [13] Decrypt Data (DES3)
    [14] Encrypt Data (AES)
    [15] Decrypt Data (AES)
    [16] Encrypt Data (XOR)
    [17] Decrypt Data (XOR)
    [18] Hide Data in Image
    [19] Extract Data from Image
    [20] Add Password
    [21] Get Password
    [22] Encrypt Config File
    [23] Decrypt Config File
    [24] Generate Report
    [0] Exit
    """)

def main():
    current_user = None
    user_actions = []
    while True:
        menu()
        choice = input("Enter your choice: ")
        if choice == '1':
            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")
            email = input("Enter email: ")
            if register_user(username, password, email):
                otp = send_otp_via_email(email)
                user_otp = input("Enter the OTP sent to your email: ")
                if verify_otp(user_otp, otp):
                    print("Registration successful")
                    log_info(f"User '{username}' registered successfully.")
                    user_actions.append("Registered successfully")
                else:
                    print("Invalid OTP. Registration failed.")
                    log_warning(f"Failed registration attempt for user '{username}' due to invalid OTP.")
        elif choice == '2':
            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")
            if login_user(username, password):
                email = input("Enter your registered email: ")
                otp = send_otp_via_email(email)
                user_otp = input("Enter the OTP sent to your email: ")
                if verify_otp(user_otp, otp):
                    current_user = username
                    print("Login successful.")
                    log_info(f"User '{username}' logged in successfully.")
                    user_actions.append("Logged in successfully")
                else:
                    print("Invalid OTP. Login failed.")
                    log_warning(f"Failed login attempt for user '{username}' due to invalid OTP.")
        elif current_user:
            try:
                if choice == '3':
                    data = input("Enter data to encrypt: ").encode()
                    password = getpass.getpass("Enter password: ")
                    encrypted_data = encryption_modules['aes_encrypt'].aes_encrypt(data, password)
                    print("Encrypted data:", encrypted_data)
                    log_info(f"User '{current_user}' encrypted data using AES.")
                    user_actions.append("Encrypted data using AES")
                elif choice == '4':
                    encrypted_data = input("Enter data to decrypt: ").encode()
                    password = getpass.getpass("Enter password: ")
                    decrypted_data = encryption_modules['aes_encrypt'].aes_decrypt(encrypted_data, password)
                    print("Decrypted data:", decrypted_data)
                    log_info(f"User '{current_user}' decrypted data using AES.")
                    user_actions.append("Decrypted data using AES")
                elif choice == '5':
                    data = input("Enter data to encrypt: ").encode()
                    private_key, public_key = encryption_modules['rsa_encrypt'].generate_rsa_keys()
                    encrypted_data = encryption_modules['rsa_encrypt'].rsa_encrypt(data, public_key)
                    print("Encrypted data:", encrypted_data)
                    log_info(f"User '{current_user}' encrypted data using RSA.")
                    user_actions.append("Encrypted data using RSA")
                elif choice == '6':
                    encrypted_data = input("Enter data to decrypt: ").encode()
                    private_key, public_key = encryption_modules['rsa_encrypt'].generate_rsa_keys()
                    decrypted_data = encryption_modules['rsa_encrypt'].rsa_decrypt(encrypted_data, private_key)
                    print("Decrypted data:", decrypted_data)
                    log_info(f"User '{current_user}' decrypted data using RSA.")
                    user_actions.append("Decrypted data using RSA")
                elif choice == '7':
                    data = input("Enter data for HMAC: ").encode()
                    key = getpass.getpass("Enter key: ").encode()
                    hmac_value = encryption_modules['hmac_integrity'].generate_hmac(data, key)
                    print("Generated HMAC:", hmac_value)
                    log_info(f"User '{current_user}' generated HMAC.")
                    user_actions.append("Generated HMAC")
                elif choice == '8':
                    data = input("Enter data for HMAC verification: ").encode()
                    key = getpass.getpass("Enter key: ").encode()
                    hmac_value = input("Enter HMAC value: ").encode()
                    if encryption_modules['hmac_integrity'].verify_integrity(data, key, hmac_value):
                        print("HMAC verified successfully.")
                        log_info(f"User '{current_user}' verified HMAC.")
                        user_actions.append("Verified HMAC")
                    else:
                        print("Failed to verify HMAC.")
                        log_warning(f"User '{current_user}' failed to verify HMAC.")
                elif choice == '9':
                    password = getpass.getpass("Enter password to hash: ")
                    salt = os.urandom(16)
                    hashed_password = encryption_modules['password_hash'].hash_password(password, salt)
                    print("Hashed password:", hashed_password)
                    log_info(f"User '{current_user}' hashed password using PBKDF2.")
                    user_actions.append("Hashed password using PBKDF2")
                elif choice == '10':
                    password = getpass.getpass("Enter password to hash: ")
                    salt = os.urandom(16)
                    hashed_password = encryption_modules['scrypt_hash'].scrypt_hash(password, salt)
                    print("Hashed password (Scrypt):", hashed_password)
                    log_info(f"User '{current_user}' hashed password using Scrypt.")
                    user_actions.append("Hashed password using Scrypt")
                elif choice == '11':
                    password = getpass.getpass("Enter password to hash: ")
                    salt = os.urandom(16)
                    hashed_password = encryption_modules['argon2_hash'].argon2_hash(password, salt)
                    print("Hashed password (Argon2):", hashed_password)
                    log_info(f"User '{current_user}' hashed password using Argon2.")
                    user_actions.append("Hashed password using Argon2")
                elif choice == '12':
                    data = input("Enter data to encrypt: ").encode()
                    key = getpass.getpass("Enter key: ").encode()
                    encrypted_data = encryption_modules['des3_encrypt'].des3_encrypt(data, key)
                    print("Encrypted data (DES3):", encrypted_data)
                    log_info(f"User '{current_user}' encrypted data using DES3.")
                    user_actions.append("Encrypted data using DES3")
                elif choice == '13':
                    encrypted_data = input("Enter data to decrypt: ").encode()
                    key = getpass.getpass("Enter key: ").encode()
                    decrypted_data = encryption_modules['des3_encrypt'].des3_decrypt(encrypted_data, key)
                    print("Decrypted data (DES3):", decrypted_data)
                    log_info(f"User '{current_user}' decrypted data using DES3.")
                    user_actions.append("Decrypted data using DES3")
                elif choice == '14':
                    data = input("Enter data to encrypt: ").encode()
                    key = get_random_bytes(16)  # 16 bytes for AES-128
                    cipher = AES.new(key, AES.MODE_CBC)
                    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
                    print("Encrypted data (AES):", cipher.iv + encrypted_data)
                    log_info(f"User '{current_user}' encrypted data using AES.")
                    user_actions.append("Encrypted data using AES")
                elif choice == '15':
                    encrypted_data = input("Enter data to decrypt: ").encode()
                    key = input("Enter key: ").encode()
                    iv = encrypted_data[:16]
                    encrypted_data = encrypted_data[16:]
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
                    print("Decrypted data (AES):", decrypted_data)
                    log_info(f"User '{current_user}' decrypted data using AES.")
                    user_actions.append("Decrypted data using AES")
                elif choice == '16':
                    data = input("Enter data to encrypt: ").encode()
                    key = getpass.getpass("Enter key: ").encode()
                    encrypted_data = encryption_modules['xor_encrypt'].xor_encrypt(data, key)
                    print("Encrypted data (XOR):", encrypted_data)
                    log_info(f"User '{current_user}' encrypted data using XOR.")
                    user_actions.append("Encrypted data using XOR")
                elif choice == '17':
                    encrypted_data = input("Enter data to decrypt: ").encode()
                    key = getpass.getpass("Enter key: ").encode()
                    decrypted_data = encryption_modules['xor_encrypt'].xor_decrypt(encrypted_data, key)
                    print("Decrypted data (XOR):", decrypted_data)
                    log_info(f"User '{current_user}' decrypted data using XOR.")
                    user_actions.append("Decrypted data using XOR")
                elif choice == '18':
                    image_path = input("Enter image path: ")
                    data = input("Enter data to hide: ").encode()
                    encryption_modules['steganography'].hide_data_in_image(image_path, data)
                    print("Data hidden in image successfully.")
                    log_info(f"User '{current_user}' hid data in image.")
                    user_actions.append("Hid data in image")
                elif choice == '19':
                    image_path = input("Enter image path: ")
                    extracted_data = encryption_modules['steganography'].extract_data_from_image(image_path)
                    print("Extracted data:", extracted_data)
                    log_info(f"User '{current_user}' extracted data from image.")
                    user_actions.append("Extracted data from image")
                elif choice == '20':
                    account = input("Enter account name: ")
                    password = getpass.getpass("Enter password to store: ")
                    add_password(current_user, account, password)
                    log_info(f"User '{current_user}' added password for account '{account}'.")
                    user_actions.append(f"Added password for account '{account}'")
                elif choice == '21':
                    account = input("Enter account name: ")
                    password = get_password(current_user, account)
                    print(f"Password for account '{account}': {password}")
                    log_info(f"User '{current_user}' retrieved password for account '{account}'.")
                    user_actions.append(f"Retrieved password for account '{account}'")
                elif choice == '22':
                    config_file = input("Enter the path to the configuration file: ")
                    key_file = input("Enter the path to the key file: ")
                    encrypt_config(config_file, key_file)
                    log_info(f"User '{current_user}' encrypted configuration file '{config_file}'.")
                    user_actions.append(f"Encrypted configuration file '{config_file}'")
                elif choice == '23':
                    config_file = input("Enter the path to the configuration file: ")
                    key_file = input("Enter the path to the key file: ")
                    decrypt_config(config_file, key_file)
                    log_info(f"User '{current_user}' decrypted configuration file '{config_file}'.")
                    user_actions.append(f"Decrypted configuration file '{config_file}'")
                elif choice == '24':
                    report_file = generate_report(current_user, user_actions)
                    log_info(f"User '{current_user}' generated report: {report_file}")
                    user_actions.append(f"Generated report: {report_file}")
                elif choice == '0':
                    break
                else:
                    print("Invalid choice. Please try again.")
                    log_warning(f"User '{current_user}' chose an invalid option.")
            except Exception as e:
                print(f"An error occurred: {e}")
                log_error(f"An error occurred for user '{current_user}': {e}")
        else:
            print("Please login or register first.")

if __name__ == "__main__":
    main()