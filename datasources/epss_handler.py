import csv
import re
from datetime import datetime
from dateutil import parser
# from loguru import logger  # Import Loguru's logger

from handlers import utils
from handlers.config_handler import ConfigHandler
from handlers.mongodb_handler import MongoDBHandler

def singleton(cls):
    """A decorator for creating a singleton class."""
    instances = {}

    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance

@singleton
class EpssHandler:
    # Define the log prefix as a class attribute for easy modification
    LOG_PREFIX = f"[{chr(int('f14ba', 16))} EPSS]"

    def __init__(self, mongo_handler, config_file='configuration.ini', logger=None):
        """
        Initialize the EpssHandler with MongoDB handler and logger.

        Args:
            mongo_handler (MongoDBHandler): Handler for MongoDB operations.
            config_file (str): Path to the configuration file.
            logger (Logger, optional): Loguru logger instance. Defaults to None.
        """
        # Bind the logger with the prefix
        self.logger = logger.bind(prefix=self.LOG_PREFIX) if logger else logger.bind(prefix=self.LOG_PREFIX)
        self.mongodb_handler = mongo_handler

        # Initialize configuration handler and retrieve EPSS-specific configurations
        config_handler = ConfigHandler(config_file)
        epss_config = config_handler.get_epss_config()
        self.url = epss_config.get('url', 'https://epss.cyentia.com/epss_scores-current.csv.gz')
        self.save_data = config_handler.get_boolean('cvemate', 'save_data', False)

    def init(self):
        """
        Initialize or update EPSS data by downloading, processing, and updating the database.
        """
        try:
            # Retrieve EPSS status from MongoDB
            epss_status = self.mongodb_handler.get_source_status('epss')
        except Exception as e:
            self.logger.error(f"Failed to retrieve EPSS status from MongoDB: {e}")
            return  # Exit early as we cannot proceed without status

        # Initialize epss_last_release_date
        epss_last_release_date = None

        # Safely extract and parse 'source_last_update' from epss_status
        if epss_status and isinstance(epss_status, dict) and 'source_last_update' in epss_status:
            try:
                epss_last_release_datetime = parser.isoparse(epss_status['source_last_update'])
                epss_last_release_date = epss_last_release_datetime.date()
            except (ValueError, TypeError) as e:
                self.logger.error(f"Error parsing 'source_last_update': {e}")
                epss_last_release_date = None  # Treat as if no valid last release date
        else:
            self.logger.debug("No existing EPSS status found or 'source_last_update' key is missing.")

        try:
            # Download the CSV data
            csv_data = utils.download_file(
                self.url,
                save_path='data/epss.csv' if self.save_data else None,
                logger=self.logger
            )
            self.logger.debug('CSV data downloaded successfully.')

            # Log the number of exploits and size of the file
            num_epss = len(csv_data.splitlines()) - 1  # Subtract 1 for the metadata line
            file_size = len(csv_data.encode('utf-8'))  # Size in bytes
            self.logger.debug(f"Downloaded {num_epss} exploits, file size: {file_size} bytes")

            # Split CSV into lines
            lines = csv_data.splitlines()

            if not lines:
                self.logger.warning('Downloaded CSV is empty.')
                return  # Exit as there's nothing to process

            # Extract model_version and score_date from the first line
            metadata_line = lines[0].lstrip('#').strip()
            metadata_pattern = r'model_version:(.*?),score_date:(.*?)$'
            metadata_match = re.match(metadata_pattern, metadata_line)

            if not metadata_match:
                self.logger.error(f"Metadata line does not match expected format: '{metadata_line}'")
                return  # Exit or handle as appropriate

            model_version, score_date_str = metadata_match.groups()

            # Parse score_date once
            try:
                score_datetime = parser.isoparse(score_date_str)
                score_date = score_datetime.date()
            except (ValueError, TypeError) as e:
                self.logger.error(f"Error parsing score_date '{score_date_str}': {e}")
                return  # Exit or handle the error appropriately

            # Determine if an update is needed based on score_date comparison
            update_needed = False
            if not epss_last_release_date:
                self.logger.info('EPSS status is missing or invalid. Proceeding to update.')
                update_needed = True
            elif score_date > epss_last_release_date:
                self.logger.info('New score_date is more recent than epss_last_release_date. Proceeding to update.')
                update_needed = True
            else:
                self.logger.info(f"Skipping update, source_last_update: {score_date}")

            if update_needed:
                # Skip the first line (metadata/comment)
                data_lines = lines[1:]

                if not data_lines:
                    self.logger.warning('No data rows found in CSV after metadata line.')
                    return  # Exit as there's no data to process

                # Parse CSV data
                reader = csv.DictReader(data_lines)
                results = []

                for row in reader:
                    # Extract data from each row with validation
                    cve_id = row.get('cve')
                    epss_score = row.get('epss')
                    percentile = row.get('percentile')

                    if not all([cve_id, epss_score, percentile]):
                        self.logger.warning(f"Incomplete data row skipped: {row}")
                        continue  # Skip incomplete rows

                    # Append the data to results
                    results.append({
                        'id': cve_id,
                        'epss': {
                            'epss_score': epss_score,
                            'percentile': percentile
                        }
                    })

                if results:
                    # Queue the CVE data for updating
                    self.mongodb_handler.queue_request('cve', results, update=True, key_field='id')
                    self.logger.info(f"Queued {len(results)} CVE entries for update.")

                    # Update the source status with the new score
                    self.mongodb_handler.update_source_status('epss', {'source_last_update': score_date_str})
                    self.logger.info(f"Updated EPSS source_last_update to {score_date_str}.")
                else:
                    self.logger.warning('No valid CVE entries found to update.')
            else:
                # No update needed; already logged above
                pass

        except Exception as e:
            self.logger.error(f"An error occurred during the EPSS update process: {e}")
            # Depending on requirements, you might want to re-raise the exception or handle it accordingly
