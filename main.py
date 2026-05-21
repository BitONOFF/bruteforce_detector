import sys
import signal
import time
import logging
from src.config import config
from src.data.parser import LogParser
from src.data.collector import LogCollector
from src.detectors.rule_based import RuleBasedDetector
from src.alerting.notifier import AlertNotifier

class BruteforceDetector:
    def __init__(self):
        self.config = config
        self.parser = LogParser(config)
        self.collector = LogCollector(config, self.parser)
        self.running = False
        self._setup_signal_handlers()
        self._setup_logging()
        self.detector = RuleBasedDetector(config)
        self.notifier = AlertNotifier(config)

    def _setup_logging(self):
        log_level = getattr(logging, self.config.get('app.log_level', 'INFO'))
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('bruteforce_detector.log')
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Starting {self.config.get('app.name')} v{self.config.get('app.version')}")

    def _setup_signal_handlers(self):
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False

    def run(self):
        self.running = True
        try:
            self.collector.start_monitoring()
            self.logger.info("Application started. Press Ctrl+C to stop.")
            while self.running:
                try:
                    logs = self.collector.collect_logs()
                    if logs:
                        self._process_logs(logs)
                    time.sleep(self.config.get('logs.check_interval', 2))
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    self.logger.info(f"Error in main loop: {e}", exc_info=True)
                    time.sleep(5)
        finally:
            self.collector.stop_monitoring()
            self.logger.info("Application stopped.")

    def _process_logs(self, logs: dict):
        for log_type, df in logs.items():
            if not df.empty:
                self.logger.info(f"Processing {len(df)} {log_type.upper()} log entries")
                self._log_statistics(df, log_type)
                attacks = self.detector.detect_bruteforce(df, log_type)
                if attacks:
                    self.notifier.notify(attacks)

    def _log_statistics(self, df, log_type: str):
        try:
            stats = {
                'total_entries': len(df),
                'failed_attempts': int(df['is_failed'].sum()) if 'is_failed' in df.columns else 0,
                'successful_attempts': int(df['is_success'].sum()) if 'is_success' in df.columns else 0,
                'unique_ips': df['source_ip'].nunique() if 'source_ip' in df.columns else 0,
                'unique_users': df['username'].nunique() if 'username' in df.columns else 0
            }
            self.logger.info(f"{log_type.upper()} Statistics: {stats}")
        except Exception as e:
            self.logger.error(f"Error calculating statistics: {e}")

def main():
    try:
        app = BruteforceDetector()
        app.run()
    except Exception as e:
        logging.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()