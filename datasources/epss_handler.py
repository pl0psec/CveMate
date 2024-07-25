import csv
import logging
from datetime import datetime
import pytz
import re
from dateutil import parser

from handlers import utils
from handlers.config_handler import ConfigHandler
from handlers.logger_handler import Logger
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

    def __init__(self, mongo_handler, config_file='configuration.ini', logger=None):
        self.banner = f"{chr(int('EAD3', 16))} {chr(int('f14ba', 16))} EPSS"

        self.mongodb_handler = mongo_handler

        config_handler = ConfigHandler(config_file)
        epss_config = config_handler.get_epss_config()
        self.url = epss_config.get('url', 'https://epss.cyentia.com/epss_scores-current.csv.gz')
        self.save_data = config_handler.get_boolean('cvemate', 'save_data', False)

        self.logger = logger or logging.getLogger()

    def init(self):
        print('\n'+self.banner)

        epss_status = self.mongodb_handler.get_source_status('epss')
        # Get the current time in UTC
        now_utc = datetime.now(pytz.utc)

        # Check if epss_status is available and its score_date
        if not epss_status or parser.isoparse(epss_status['source_last_update']).date() < now_utc.date():

            self.logger.info('Performing the required action because no EPSS status or its score_date is older than today.')

            # Call the new download_file method
            csv_data = utils.download_file(self.url, save_path='data/epss.csv' if self.save_data else None, logger=self.logger)

            # Log the number of exploits and size of the file
            num_epss = len(csv_data.splitlines()) - 1  # Subtract 1 for the header row
            file_size = len(csv_data.encode('utf-8'))  # Size in bytes
            self.logger.info(f"[{chr(int('f14ba', 16))} EPSS] Downloaded {num_epss} exploits, file size: {file_size} bytes")

            # Initialize an empty list for the results
            results = []

             # Process the CSV data
            lines = csv_data.splitlines()

            # Extract model_version and score_date using regex
            # #model_version:v2023.03.01,score_date:2024-07-24T00:00:00+0000
            model_version, score_date = re.findall(r'model_version:(.*?),score_date:(.*?)$', csv_data.splitlines()[0].lstrip('#'))[0]

            # Skip the first line (metadata/comment)
            lines = lines[1:]
            reader = csv.DictReader(lines)

            for row in reader:
                # Extract data from each row
                cve_id = row['cve']
                epss_score = row['epss']
                percentile = row['percentile']

                # Append the data to results
                results.append({'id': cve_id, 'epss': {'epss_score': epss_score, 'percentile': percentile}})


            self.mongodb_handler.queue_request('cve', results, update=True, key_field='id')
            self.mongodb_handler.update_source_status('epss', {'source_last_update':score_date})

        else:
            # Print a message if the current version is up-to-date
            self.logger.info(f"Skipping update, source_last_update: {epss_status['source_last_update']}")
