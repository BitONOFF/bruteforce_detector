import logging
from datetime import datetime
from typing import Dict, List
import requests

logger = logging.getLogger(__name__)

class AlertNotifier:
    def __init__(self, config):
        self.config = config
        self.alert_cooldown = {}
        self.cooldown_minutes = config.get('alerting.cooldown_minutes', 1)
        self.telegram_bot_token = config.get('alerting.telegram.bot_token', '')
        self.telegram_chat_id = config.get('alerting.telegram.chat_id', '')

    def notify(self, attacks: List[Dict]):
        if not attacks:
            return
        logger.warning(f"\n{'!' * 50}")
        logger.warning("BRUTEFORCE ATTACK DETECTED!")
        logger.warning(f"{'!' * 50}")
        for attack in attacks:
            attack_key = f"{attack['type']}_{attack.get('source_ip', '')}_{attack.get('username', '')}"
            if attack_key in self.alert_cooldown:
                last_alert = self.alert_cooldown[attack_key]
                time_since = (datetime.now() - last_alert).total_seconds() / 60
                if time_since < self.cooldown_minutes:
                    continue
            self._format_and_send(attack)
            self.alert_cooldown[attack_key] = datetime.now()

    def _format_and_send(self, attack: Dict):
        severity = attack.get('severity', 'MEDIUM')
        log_type = attack.get('log_type', 'UNKNOWN')
        message = f"""
        {severity} {attack['type'].upper()} DETECTED
        Protocol: {log_type.upper()}
        Reason: {attack['reason']}
        """
        if 'source_ip' in attack:
            message += f"Attacker IP: {attack['source_ip']}\n"
        if 'username' in attack:
            message += f"Target user: {attack['username']}\n"
        if 'failed_attempts' in attack:
            message += f"Failed attempts: {attack['failed_attempts']}\n"
        if 'rate_per_second' in attack:
            message += f"Attack rate: {attack['rate_per_second']:.1f} attempts/sec\n"
        if 'time_range' in attack:
            message += f"Time range: {attack['time_range']}\n"
        logger.warning(message)
        channels = self.config.get('alerting.channels', ['console'])
        if 'telegram' in channels:
            self._send_telegram(attack, severity)

    def _send_telegram(self, attack: Dict, severity: str):
        try:
            if not self.telegram_bot_token or not self.telegram_chat_id:
                logger.warning("Telegram bot_token or chat_id not configured")
                return
            severity_emoji = "🔴" if severity == 'HIGH' else "🟡" if severity == 'MEDIUM' else "🔵"
            message = (f"{severity_emoji} Bruteforce Attack Detected! {severity_emoji}\n"
                       f"Type: {attack['type']}\n"
                       f"Protocol: {attack.get('log_type', 'UNKNOWN').upper()}\n"
                       f"Reason: {attack['reason']}\n")
            if 'source_ip' in attack:
                message += f"Attacker IP: `{attack['source_ip']}`\n"
            if 'username' in attack:
                message += f"Target user: `{attack['username']}`\n"
            if 'failed_attempts' in attack:
                message += f"Failed attempts: {attack['failed_attempts']}\n"
            if 'rate_per_second' in attack:
                message += f"Attack rate: {attack['rate_per_second']:.1f}/sec\n"
            message += f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'disable_notification': severity != 'HIGH'
            }
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                logger.info(f"Telegram alert sent successfully")
            else:
                logger.error(f"Failed to sent Telegram alert: {response.status_code} - {response.text}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending Telegram alert: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in Telegram sender: {e}")