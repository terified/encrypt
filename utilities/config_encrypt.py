from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Генерация ключа для шифрования конфигурации
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

# Шифрование конфигурационного файла
def encrypt_config(config_file, key_file):
    key = load_key(key_file)
    cipher = AES.new(key, AES.MODE_CBC)
    with open(config_file, 'rb') as file:
        config_data = file.read()
    encrypted_data = cipher.encrypt(pad(config_data, AES.block_size))
    with open(config_file, 'wb') as file:
        file.write(cipher.iv + encrypted_data)
    print(f"Configuration file '{config_file}' encrypted successfully.")

# Дешифрование конфигурационного файла
def decrypt_config(config_file, key_file):
    key = load_key(key_file)
    with open(config_file, 'rb') as file:
        iv = file.read(16)
        encrypted_data = file.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    with open(config_file, 'wb') as file:
        file.write(decrypted_data)
    print(f"Configuration file '{config_file}' decrypted successfully.")

# Пример использования
if __name__ == "__main__":
    key = generate_key()
    save_key(key, 'config_key.key')
    encrypt_config('config.json', 'config_key.key')
    decrypt_config('config.json', 'config_key.key')