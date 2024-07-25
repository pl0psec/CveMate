from datetime import datetime
import inspect

class Logger:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

    # Add a class variable to store the maximum log level
    max_log_level = 'INFO'

    # Levels in order of severity
    levels = {'DEBUG': 1, 'INFO': 2, 'WARNING': 3, 'ERROR': 4, 'SUCCESS': 5}

    @staticmethod
    def set_max_log_level(level):
        # Convert the level to uppercase to make the comparison case-insensitive
        upper_level = level.upper()
        if upper_level in Logger.levels:
            Logger.max_log_level = upper_level
        else:
            raise ValueError(f"Invalid log level: {level}")

    @staticmethod
    def log(message, level='INFO'):
        # Check if the log level of the message is equal or higher than the max_log_level
        if Logger.levels[level] >= Logger.levels[Logger.max_log_level]:
            color = {
                'DEBUG': Logger.CYAN,
                'INFO': Logger.BLUE,
                'WARNING': Logger.YELLOW,
                'ERROR': Logger.RED,
                'SUCCESS': Logger.GREEN
            }.get(level, Logger.BLUE)

            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Use inspect to find the module name
            stack = inspect.stack()
            module = inspect.getmodule(stack[1][0])
            module_name = module.__name__ if module else '__main__'

            print(f"{timestamp} | {level} | {module_name} | {color}{message}{Logger.RESET}")
