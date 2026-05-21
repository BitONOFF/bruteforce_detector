import pandas as pd
from pathlib import Path
from typing import Dict
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger(__name__)

class LogCollector:
    def __init__(self, config, parser):
        self.config = config
        self.parser = parser
        self.log_position = {}
        self._setup_watchdog()

    def _setup_watchdog(self):
        self.observer = Observer()
        self.event_handler = LogFileEventHandler(self)
        log_paths = [
            self.config.get('logs.ssh_log_path'),
            self.config.get('logs.ftp_log_path')
        ]
        watched_dirs = set()
        for log_path in log_paths:
            if log_path:
                path = Path(log_path)
                directory = path.parent
                if str(directory) not in watched_dirs:
                    self.observer.schedule(self.event_handler, str(directory), recursive=False)
                    watched_dirs.add(str(directory))
                logger.info(f"Started watching directory for file: {path}")

    def start_monitoring(self):
        self.observer.start()
        logger.info("Log monitoring started")

    def stop_monitoring(self):
        self.observer.stop()
        self.observer.join()
        logger.info("Log monitoring stopped")

    def collect_logs(self) -> Dict[str, pd.DataFrame]:
        logs = {}
        ssh_path = self.config.get('logs.ssh_log_path')
        if ssh_path and Path(ssh_path).exists():
            ssh_logs = self._collect_from_file(ssh_path, 'ssh')
            if not ssh_logs.empty:
                logs['ssh'] = ssh_logs
        ftp_path = self.config.get('logs.ftp_log_path')
        if ftp_path and Path(ftp_path).exists():
            ftp_logs = self._collect_from_file(ftp_path, 'ftp')
            if not ftp_logs.empty:
                logs['ftp'] = ftp_logs
        return logs

    def _collect_from_file(self, file_path: str, log_type: str) -> pd.DataFrame:
        try:
            if file_path not in self.log_position:
                self.log_position[file_path] = 0
            new_logs, new_position = self.parser.parse_new_entries(file_path, self.log_position[file_path])
            self.log_position[file_path] = new_position
            if not new_logs.empty:
                logger.info(f"Collected {len(new_logs)} new {log_type} log entries")
            return new_logs
        except Exception as e:
            logger.error(f"Error collecting {log_type} logs from {file_path}: {e}")
            return pd.DataFrame()

class LogFileEventHandler(FileSystemEventHandler):
    def __init__(self, collector):
        self.collector = collector

    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            ssh_path = self.collector.config.get('logs.ssh_log_path')
            ftp_path = self.collector.config.get('logs.ftp_log_path')
            if file_path == ssh_path or file_path == ftp_path:
                logger.debug(f"Log file modified: {file_path}")