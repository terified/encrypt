# Encryption Tool

## Описание
Это инструмент для шифрования и управления паролями, который поддерживает различные методы шифрования и хеширования. Он также включает функции для регистрации пользователей, входа в систему, и двухфакторной аутентификации (2FA).

## Установка
1. Склонируйте репозиторий:
    ```bash
    git clone https://github.com/yourusername/encryption_tool.git
    ```
2. Перейдите в директорию проекта:
    ```bash
    cd encryption_tool
    ```
3. Установите зависимости:
    ```bash
    pip install -r requirements.txt
    ```

## Использование
### Регистрация пользователя
```bash
python utilities/cli.py register --username <username> --password <password> --email <email>
```

### Вход пользователя
```bash
python utilities/cli.py login --username <username> --password <password>
```

### Шифрование текста (AES)
```bash
python utilities/cli.py encrypt --data <data> --key <key>
```

### Дешифрование текста (AES)
```bash
python utilities/cli.py decrypt --data <data> --key <key>
```

### Генерация HMAC
```bash
python utilities/cli.py generate-hmac --data <data> --key <key>
```

### Проверка HMAC
```bash
python utilities/cli.py verify-hmac --data <data> --key <key>
```

### Хеширование пароля (PBKDF2)
```bash
python utilities/cli.py hash-password --password <password>
```

### Добавление пароля для аккаунта
```bash
python utilities/cli.py add-password --account <account> --password <password>
```

### Получение пароля для аккаунта
```bash
python utilities/cli.py get-password --account <account>
```

### Шифрование конфигурационного файла
```bash
python utilities/cli.py encrypt-config --config-file <config_file> --key-file <key_file>
```

### Дешифрование конфигурационного файла
```bash
python utilities/cli.py decrypt-config --config-file <config_file> --key-file <key_file>
```

### Генерация отчета
```bash
python utilities/cli.py generate-report
```

## Логирование и мониторинг
Все действия пользователей и ошибки логируются в директорию `logs` с указанием времени и даты.

## Генерация отчетов
Отчеты о выполненных действиях пользователей автоматически генерируются и сохраняются в директорию `reports`.