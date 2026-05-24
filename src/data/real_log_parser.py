import re
import csv
from typing import List, Optional


class SSHLogParser:
    def __init__(self):
        # Базовое выражение для структуры строки
        self.base_regex = re.compile(
            r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+\d{2}:\d{2})\s+"
            r"(?P<host>\S+)\s+"
            r"(?P<process>sshd[\w-]*)(?:\[\d+\])?:\s+"
            r"(?P<message>.*)$"
        )

    def parse_line(self, line: str) -> Optional[dict]:
        line = line.strip()
        if not line:
            return None

        match = self.base_regex.match(line)
        if not match:
            return None

        data = match.groupdict()
        ts = data["timestamp"]
        msg = data["message"]

        source_ip = "None"
        username = "None"
        event_type = "None"
        status = "None"
        details = msg

        # Неудачная попытка аутентификации
        if "Failed password" in msg:
            m = re.search(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)", msg)
            if m:
                username = m.group("user")
                source_ip = m.group("ip")
            event_type = "login_attempt"
            status = "FAILED"
            details = "Failed password authentication"

        # Успешный вход
        elif "Accepted password" in msg:
            m = re.search(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)", msg)
            if m:
                username = m.group("user")
                source_ip = m.group("ip")
            event_type = "login_attempt"
            status = "SUCCESS"
            details = "Successful login"

        # Запрос на отключение/Отключение от пользователя
        elif "Received disconnect" in msg or "Disconnected from" in msg:
            m = re.search(r"from (user )?(?P<user>\S+ )?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", msg)
            if m:
                source_ip = m.group("ip")
                if m.group("user"):
                    username = m.group("user").strip()
            event_type = "connection_close"
            status = "SUCCESS"
            details = "Disconnected by user"

        # Сброс/закрытие соединения до авторизации
        elif "Connection closed" in msg:
            m = re.search(r"authenticating user (?P<user>\S+) (?P<ip>\S+)", msg)
            if m:
                username = m.group("user")
                source_ip = m.group("ip")
            else:
                # Попытка вытащить IP если пользователя определить не удалось
                m_ip = re.search(r"from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", msg)
                if m_ip:
                    source_ip = m_ip.group("ip")
            event_type = "connection_close"
            status = "FAILED"
            details = "Connection closed during pre-authentication"

        # Информационные сообщения PAM сессии sshd
        elif "pam_unix(sshd:session): session opened" in msg:
            m = re.search(r"session opened for user (?P<user>\w+)", msg)
            if m:
                username = m.group("user")
            event_type = "session_open"
            status = "SUCCESS"
            details = "PAM session opened"

        elif "pam_unix(sshd:session): session closed" in msg:
            m = re.search(r"session closed for user (?P<user>\w+)", msg)
            if m:
                username = m.group("user")
            event_type = "session_close"
            status = "SUCCESS"
            details = "PAM session closed"

        else:
            # Игнор технических сообщений sshd (listening on port, penalty и т.д.)
            return None

        return {
            "timestamp": ts,
            "source_ip": source_ip,
            "username": username,
            "protocol": "ssh",
            "event_type": event_type,
            "status": status,
            "details": details
        }

    def process_file(self, input_file_path: str, output_csv_path: str):
        headers = ["timestamp", "source_ip", "username", "protocol", "event_type", "status", "details"]

        with open(input_file_path, "r", encoding="utf-8") as infile, \
                open(output_csv_path, "w", newline="", encoding="utf-8") as outfile:

            writer = csv.DictWriter(outfile, fieldnames=headers)
            writer.writeheader()

            for line in infile:
                parsed_data = self.parse_line(line)
                if parsed_data:
                    writer.writerow(parsed_data)
