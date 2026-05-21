import pandas as pd
from typing import Tuple
import re
import logging

logger = logging.getLogger(__name__)

class LogParser:
    EXPECTED_COLUMNS = [
        'timestamp',
        'source_ip',
        'username',
        'protocol',
        'event_type',
        'status',
        'details'
    ]

    SSH_ERRORS = [
        'invalid password',
        'authentication failure',
        'failed password',
        'connection closed'
    ]

    IP_PATTERN = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

    def __init__(self, config):
        self.config = config
        self._setup_logging()

    def _setup_logging(self):
        try:
            log_level_str = self.config.get('app.log_level', 'INFO')
            if log_level_str is None:
                log_level_str = 'INFO'
                logger.warning("log_level not found in config, using INFO")
            log_level = getattr(logging, log_level_str.upper())
            logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        except AttributeError as e:
            logger.error(f"Invalid log_level in config: {log_level_str}, using INFO")
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # def parse_csv(self, file_path: str) -> pd.DataFrame:
    #     try:
    #         logger.info(f"Parsing log file: {file_path}")
    #         df = pd.read_csv(
    #             file_path,
    #             parse_dates=['timestamp'],
    #             infer_datetime_format=True,
    #             on_bad_lines='warn'
    #         )
    #         missing_cols = set(self.EXPECTED_COLUMNS) - set(df.columns)
    #         if missing_cols:
    #             logger.warning(f"Missing columns in log file: {missing_cols}")
    #             for col in missing_cols:
    #                 df[col] = np.nan
    #         df = self._clean_data(df)
    #         df = self._extract_features(df)
    #         logger.info(f"Successfully parsed {len(df)} log entries")
    #         return df
    #     except FileNotFoundError:
    #         logger.error(f"Log file not found: {file_path}")
    #         return pd.DataFrame(columns=self.EXPECTED_COLUMNS)
    #     except Exception as e:
    #         logger.error(f"Error parsing log file: {e}")
    #         raise

    def _clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        initial_count = len(df)
        df = df.drop_duplicates()
        logger.debug(f"Removed {initial_count - len(df)} duplicates entries")
        if 'source_ip' in df.columns:
            df['source_ip'] = df['source_ip'].astype(str).apply(self._clean_ip)
        if 'username' in df.columns:
            df['username'] = df['username'].astype(str).str.lower().str.strip()
            df['username'] = df['username'].replace(['nan', 'none', ''], 'unknown')
        if 'status' in df.columns:
            df['status'] = df['status'].astype(str).str.upper().str.strip()
        if 'event_type' in df.columns:
            df['event_type'] = df['event_type'].astype(str).str.lower().str.strip()
        important_cols = ['timestamp', 'source_ip']
        df = df.dropna(subset=important_cols)
        df = df.sort_values('timestamp').reset_index(drop=True)
        return df

    def _clean_ip(self, ip: str) -> str:
        if pd.isna(ip):
            return '0.0.0.0'
        ip_str = str(ip).strip()
        match = re.search(self.IP_PATTERN, ip_str)
        if match:
            return match.group()
        return '0.0.0.0'

    def _extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        if 'timestamp' in df.columns:
            df['hour'] = df['timestamp'].dt.hour
            df['day_of_week'] = df['timestamp'].dt.dayofweek
            df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        if 'details' in df.columns:
            df['error_type'] = df['details'].astype(str).apply(self._classify_errors)
        df['is_failed'] = df['status'].isin(['FAILED', 'ERROR', 'DENIED']).astype(int)
        df['is_success'] = df['status'].isin(['SUCCESS', 'OK']).astype(int)
        if 'protocol' not in df.columns or df['protocol'].isna().all():
            df['protocol'] = self._infer_protocol(df)
        return df

    def _classify_errors(self, detail: str) -> str:
        if pd.isna(detail):
            return 'unknown'
        detail_lower = detail.lower()
        for error in self.SSH_ERRORS:
            if error in detail_lower:
                return error.replace(' ', '_')
        return 'other'

    def _infer_protocol(self, df: pd.DataFrame) -> pd.Series:
        protocols = []
        for idx, row in df.iterrows():
            if 'ssh' in str(row.get('details', '')).lower():
                protocols.append('ssh')
            elif 'ftp' in str(row.get('details', '')).lower():
                protocols.append('ftp')
            else:
                protocols.append('unknowns')
        return pd.Series(protocols, index=df.index)

    def parse_new_entries(self, file_path: str, last_position: int = 0) -> Tuple[pd.DataFrame, int]:
        try:
            df = pd.read_csv(
                file_path,
                parse_dates=['timestamp'],
                on_bad_lines='warn',
                encoding='utf-8'
            )
            if df.empty:
                return df, last_position
            if last_position > 0 and last_position < len(df):
                df = df.iloc[last_position:]
            elif last_position >= len(df):
                return pd.DataFrame(columns=self.EXPECTED_COLUMNS), last_position
            df = self._clean_data(df)
            df = self._extract_features(df)
            new_position = last_position + len(df)
            logger.debug(f"Parsed {len(df)} new entries, new position: {new_position}")
            return df, new_position
        except Exception as e:
            logger.error(f"Error parsing new entries: {e}")
            return pd.DataFrame(columns=self.EXPECTED_COLUMNS), last_position