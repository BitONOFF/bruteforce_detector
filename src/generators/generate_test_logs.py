import csv
import random
from datetime import datetime, timedelta
from pathlib import Path


def generate_ssh_logs(output_path: str, num_entries: int = 1000):
    """Генерация тестовых SSH логов"""

    protocols = ['ssh']
    statuses = ['SUCCESS', 'FAILED']
    usernames = ['admin', 'root', 'user', 'test', 'ubuntu', 'centos', 'debian']
    error_messages = [
        'Invalid password',
        'Connection closed',
        'Authentication failure',
        'Failed password',
        'Timeout'
    ]

    # Генерируем нормальные IP
    normal_ips = [f"192.168.1.{i}" for i in range(1, 51)]

    # Генерируем подозрительные IP (для bruteforce)
    suspicious_ips = [
        f"10.0.0.{i}" for i in range(1, 6)  # 5 подозрительных IP
    ]

    with open(output_path, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'source_ip', 'username', 'protocol', 'event_type', 'status', 'details']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        base_time = datetime.now() - timedelta(hours=24)

        for i in range(num_entries):
            # Определяем, будет ли это нормальный или подозрительный запрос
            if random.random() < 0.1:  # 10% подозрительных запросов
                ip = random.choice(suspicious_ips)
                status = 'FAILED' if random.random() < 0.9 else 'SUCCESS'  # 90% неудач для подозрительных
            else:
                ip = random.choice(normal_ips)
                status = random.choices(['SUCCESS', 'FAILED'], weights=[0.7, 0.3])[0]

            timestamp = base_time + timedelta(minutes=i * 5)

            # Для подозрительных IP используем разные имена пользователей
            if ip in suspicious_ips:
                username = random.choice(usernames)
            else:
                username = random.choice(['admin', 'user'])  # Нормальные пользователи

            details = ''
            if status == 'FAILED':
                details = random.choice(error_messages)

            writer.writerow({
                'timestamp': timestamp.isoformat(),
                'source_ip': ip,
                'username': username,
                'protocol': 'ssh',
                'event_type': 'login_attempt',
                'status': status,
                'details': details
            })

    print(f"Generated {num_entries} SSH log entries to {output_path}")


def generate_ftp_logs(output_path: str, num_entries: int = 500):
    """Генерация тестовых FTP логов"""

    protocols = ['ftp']
    statuses = ['SUCCESS', 'FAILED']
    usernames = ['ftpuser', 'anonymous', 'admin', 'user']

    with open(output_path, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'source_ip', 'username', 'protocol', 'event_type', 'status', 'details']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        base_time = datetime.now() - timedelta(hours=12)

        for i in range(num_entries):
            timestamp = base_time + timedelta(minutes=i * 10)
            ip = f"10.0.1.{random.randint(1, 100)}"
            username = random.choice(usernames)
            status = random.choices(['SUCCESS', 'FAILED'], weights=[0.8, 0.2])[0]

            details = ''
            if status == 'FAILED':
                details = 'Invalid password' if random.random() < 0.7 else 'Connection refused'

            writer.writerow({
                'timestamp': timestamp.isoformat(),
                'source_ip': ip,
                'username': username,
                'protocol': 'ftp',
                'event_type': 'login_attempt',
                'status': status,
                'details': details
            })

    print(f"Generated {num_entries} FTP log entries to {output_path}")


if __name__ == "__main__":
    # Создаем папку logs если её нет
    Path("../../logs").mkdir(exist_ok=True)

    # Генерируем тестовые логи
    generate_ssh_logs("../../logs/ssh_logs.csv", 1500)
    generate_ftp_logs("../../logs/ftp_logs.csv", 500)

    print("\nTest logs generated successfully!")
    print("You can now run the bruteforce detector with: python main.py")