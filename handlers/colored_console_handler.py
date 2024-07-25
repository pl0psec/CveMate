import logging
from datetime import datetime

class ColoredConsoleHandler(logging.Handler):
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

    LEVEL_COLORS = {
        logging.DEBUG: CYAN,
        logging.INFO: BLUE,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: RED,
        'SUCCESS': GREEN
    }

    def emit(self, record):
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            color = self.LEVEL_COLORS.get(record.levelno, self.BLUE)
            module_name = record.module
            message = self.format(record)
            print(f"{timestamp} | {record.levelname} | {module_name} | {color}{message}{self.RESET}")
        except Exception:
            self.handleError(record)
