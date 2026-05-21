import pandas as pd
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)

class RuleBasedDetector:
    def __init__(self, config):
        self.config = config
        self.thresholds = config.get('detection.thresholds', {})

    def detect_bruteforce(self, df: pd.DataFrame, log_type: str) -> List[Dict]:
        attacks = []
        try:
            ip_attacks = self._detect_by_ip(df, log_type)
            attacks.extend(ip_attacks)
            user_attacks = self._detect_by_user(df, log_type)
            attacks.extend(user_attacks)
            rate_attacks = self._detect_by_rate(df, log_type)
            attacks.extend(rate_attacks)
            logger.info(f"Rule-based detection for {log_type}: found {len(attacks)} potential attacks")
        except Exception as e:
            logger.error(f"Error in rule-based detection: {e}")
        return attacks

    def _detect_by_ip(self, df: pd.DataFrame, log_type: str) -> List[Dict]:
        attacks = []
        if df.empty:
            return attacks
        ip_stats = df.groupby('source_ip').agg({
            'is_failed': 'sum',
            'is_success': 'sum',
            'timestamp': ['min', 'max', 'count'],
            'username': lambda x: x.nunique()
        }).reset_index()
        ip_stats.columns = ['source_ip', 'failed_count', 'success_count', 'first_attempt', 'last_attempt', 'total_attempts', 'unique_users']
        max_failed = self.thresholds.get('max_failed_attempts', 10)
        min_users = self.thresholds.get('min_unique_usernames', 3)
        for _, row in ip_stats.iterrows():
            if row['failed_count'] >= max_failed:
                attack = {
                    'type': 'bruteforce_ip',
                    'log_type': log_type,
                    'source_ip': row['source_ip'],
                    'severity': 'HIGH',
                    'reason': f"Too many failed attempts ({row['failed_count']}/{max_failed})",
                    'failed_attempts': int(row['failed_count']),
                    'success_attempts': int(row['success_count']),
                    'total_attempts': int(row['total_attempts']),
                    'unique_users': int(row['unique_users']),
                    'time_range': f"{row['first_attempt']} to {row['last_attempt']}"
                }
                attacks.append(attack)
            elif row['unique_users'] >= min_users:
                attack = {
                    'type': 'user_enumeration',
                    'log_type': log_type,
                    'source_ip': row['source_ip'],
                    'severity': 'MEDIUM',
                    'reason': f"Multiple users from single IP ({row['unique_users']}/{min_users})",
                    'failed_attempts': int(row['failed_count']),
                    'success_attempts': int(row['success_count']),
                    'total_attempts': int(row['total_attempts']),
                    'unique_users': int(row['unique_users']),
                    'time_range': f"{row['first_attempt']} to {row['last_attempt']}"
                }
                attacks.append(attack)
        return attacks

    def _detect_by_user(self, df: pd.DataFrame, log_type: str) -> List[Dict]:
        attacks = []
        if df.empty:
            return attacks
        user_stats = df.groupby('username').agg({
            'is_failed': 'sum',
            'source_ip': lambda x: x.nunique()
        }).reset_index()
        user_stats.columns = ['username', 'failed_count', 'unique_ips']
        for _, row in user_stats.iterrows():
            if row['failed_count'] >= 5 and row['unique_ips'] >= 3:
                attack = {
                    'type': 'distributed_bruteforce',
                    'log_type': log_type,
                    'username': row['username'],
                    'severity': 'HIGH',
                    'reason': f"Multiple failed attempts from different IPs",
                    'failed_attempts': int(row['failed_count']),
                    'unique_ips': int(row['unique_ips'])
                }
                attacks.append(attack)
        return attacks

    def _detect_by_rate(self, df:pd.DataFrame, log_type: str) -> List[Dict]:
        attacks = []
        if len(df) < 2:
            return attacks
        df = df.sort_values('timestamp')
        df['time_diff'] = df['timestamp'].diff().dt.total_seconds()
        max_rate = self.thresholds.get('max_attempts_per_second', 5)
        for ip in df['source_ip'].unique():
            ip_logs = df[df['source_ip'] == ip]
            if len(ip_logs) < 5:
                continue
            for i in range(0, len(ip_logs) - 4):
                window = ip_logs.iloc[i:i+5]
                time_span = (window['timestamp'].iloc[-1] - window['timestamp'].iloc[0]).total_seconds()
                if time_span > 0:
                    rate = 5 / time_span
                    if rate > max_rate:
                        attack = {
                            'type': 'high_rate_attack',
                            'log_type': log_type,
                            'source_ip': ip,
                            'severity': 'HIGH',
                            'reason': f"High attempt rate detected: {rate:.1f} attempts/sec (threshold: {max_rate})",
                            'attempts_in_window': 5,
                            'time_window_seconds': time_span,
                            'rate_per_second': rate,
                            'start_time': window['timestamp'].iloc[0],
                            'end_time': window['timestamp'].iloc[-1]
                        }
                        attacks.append(attack)
                        break
        return attacks