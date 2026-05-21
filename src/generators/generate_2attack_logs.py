import csv
import random
from datetime import datetime, timedelta
from collections import defaultdict


def create_ftp_logs_without_false_positives():
    """Создание логов БЕЗ ложных срабатываний на distributed bruteforce"""

    base_time = datetime.now() - timedelta(days=30)

    with open('../../logs/ftp_logs.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'source_ip', 'username', 'protocol',
                         'event_type', 'status', 'details'])

        logs = []

        # ===== АТАКА 1 =====
        attack1_ip = "10.0.0.11"
        attack1_start = base_time + timedelta(days=5, hours=10)

        for i in range(12):
            timestamp = attack1_start + timedelta(seconds=i * 20)
            username = f"attack_user_{i % 3 + 1}"

            logs.append([
                timestamp.isoformat(),
                attack1_ip,
                username,
                'ftp',
                'login_attempt',
                'FAILED',
                'Invalid password'
            ])

        # ===== АТАКА 2 =====
        attack2_ip = "192.168.1.100"
        attack2_start = base_time + timedelta(days=10, hours=15)

        for i in range(15):
            timestamp = attack2_start + timedelta(seconds=i * 20)
            username = f"hacked_{i % 4 + 1}"

            logs.append([
                timestamp.isoformat(),
                attack2_ip,
                username,
                'ftp',
                'login_attempt',
                'FAILED',
                'Authentication failed'
            ])

        # ===== НОРМАЛЬНЫЕ ЛОГИ БЕЗ DISTRIBUTED BRUTEFORCE =====
        # Создаем 500 уникальных пользователей
        # Каждый пользователь будет иметь МАКСИМУМ 3 неудачных попытки за весь месяц

        # Словарь для отслеживания неудачных попыток по пользователям
        user_failed_counts = defaultdict(int)

        # Создаем 1000 уникальных IP
        for ip_num in range(1, 1001):
            ip = f"172.16.{ip_num // 256}.{ip_num % 256}"

            # Каждому IP назначаем ОДНОГО пользователя
            user_id = random.randint(1, 500)
            username = f"user_{user_id}"

            # Создаем 5 записей для этого IP
            for attempt in range(5):
                # Случайное время за 30 дней
                day = random.randint(1, 30)
                hour = random.randint(0, 23)
                minute = random.randint(0, 59)
                second = random.randint(0, 59)

                timestamp = base_time + timedelta(days=day, hours=hour, minutes=minute, seconds=second)

                # Решаем, успешная или неудачная попытка
                # Если у пользователя уже 3 неудачных, делаем только успешные
                if user_failed_counts[username] >= 3:
                    # Только успешные
                    status = 'SUCCESS'
                    details = ''
                else:
                    # 90% успешных, 10% неудачных
                    if random.random() < 0.9:
                        status = 'SUCCESS'
                        details = ''
                    else:
                        status = 'FAILED'
                        details = 'Wrong password'
                        user_failed_counts[username] += 1

                logs.append([
                    timestamp.isoformat(),
                    ip,
                    username,
                    'ftp',
                    'login_attempt',
                    status,
                    details
                ])

        # Проверяем, что у каждого пользователя <= 3 неудачных попыток
        print("=== ПРОВЕРКА DISTRIBUTED BRUTEFORCE ===")
        problematic_users = []
        for user, count in user_failed_counts.items():
            if count > 3:
                problematic_users.append((user, count))

        if problematic_users:
            print(f"⚠️  Проблемные пользователи ( >3 неудачных попыток): {len(problematic_users)}")
            for user, count in problematic_users[:10]:
                print(f"  {user}: {count} неудачных попыток")
        else:
            print("✓ У всех пользователей ≤3 неудачных попыток")

        # Проверяем user enumeration по IP
        print("\n=== ПРОВЕРКА USER ENUMERATION ===")
        ip_users = defaultdict(set)
        for log in logs:
            ip_users[log[1]].add(log[2])

        problematic_ips = []
        for ip, users in ip_users.items():
            if len(users) > 2 and ip not in [attack1_ip, attack2_ip]:  # 2 - чтобы не детектилось
                problematic_ips.append((ip, len(users)))

        if problematic_ips:
            print(f"⚠️  Проблемные IP ( >2 пользователей): {len(problematic_ips)}")
            for ip, count in problematic_ips[:10]:
                print(f"  {ip}: {count} пользователей")
        else:
            print("✓ У всех нормальных IP ≤2 пользователей")

        # Сортируем и записываем
        logs.sort(key=lambda x: x[0])

        # Дополнительная проверка перед записью
        print("\n=== ФИНАЛЬНАЯ ПРОВЕРКА ===")
        print(f"Всего записей: {len(logs)}")
        print(f"Атака 1: {attack1_ip} - 12 неудачных попыток")
        print(f"Атака 2: {attack2_ip} - 15 неудачных попыток")

        # Подсчет неудачных попыток по пользователям для проверки
        print("\nТоп пользователей по неудачным попыткам:")
        user_stats = defaultdict(int)
        for log in logs:
            if log[5] == 'FAILED':
                user_stats[log[2]] += 1

        # Сортируем и выводим топ
        sorted_users = sorted(user_stats.items(), key=lambda x: x[1], reverse=True)
        for user, count in sorted_users[:10]:
            print(f"  {user}: {count} неудачных попыток")

        writer.writerows(logs)

        print(f"\n✓ Файл создан: ftp_logs.csv")


create_ftp_logs_without_false_positives()