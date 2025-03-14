import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Генерация ключа для шифрования данных пользователя
def generate_key():
    return get_random_bytes(16)  # 16 байт для AES-128

# Сохранение ключа в файл
def save_key(key, key_file):
    with open(key_file, 'wb') as file:
        file.write(key)

# Загрузка ключа из файла
def load_key(key_file):
    with open(key_file, 'rb') as file:
        return file.read()

# Шифрование данных
def encrypt_data(data, key_file):
    key = load_key(key_file)
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv + encrypted_data

# Дешифрование данных
def decrypt_data(encrypted_data, key_file):
    key = load_key(key_file)
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode()

# Регистрация пользователя
def register_user(username, password, email):
    key_file = f'{username}_key.key'
    if not os.path.exists(key_file):
        key = generate_key()
        save_key(key, key_file)
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    encrypted_email = encrypt_data(email, key_file)
    with open('users.txt', 'a') as file:
        file.write(f'{username}:{hashed_password}:{encrypted_email.hex()}\n')
    return True

# Вход пользователя
def login_user(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open('users.txt', 'r') as file:
        for line in file:
            user, stored_password, _ = line.strip().split(':')
            if user == username and stored_password == hashed_password:
                return True
    return False