import json
import logging
from datetime import datetime
import pytz
from dateutil import parser

from handlers import utils
from handlers.config_handler import ConfigHandler
from handlers.logger_handler import Logger
from handlers.mongodb_handler import MongoDBHandler

def singleton(cls):
    instances = {}

    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance

@singleton
class CisaHandler:

    def __init__(self, mongo_handler, config_file='configuration.ini', logger=None):
        self.banner = f"{chr(int('EAD3', 16))} {chr(int('f14ba', 16))} CISA's Kev"

        self.mongodb_handler = mongo_handler

        config_handler = ConfigHandler(config_file)

        cisa_config = config_handler.get_config_section('cisa')
        self.url = cisa_config.get('url')
        self.save_data = config_handler.get_boolean('cvemate', 'save_data', False)

        self.logger = logger or logging.getLogger()        


    def init(self):
        print('\n'+self.banner)


        cisa_status = self.mongodb_handler.get_source_status('cisa')
        # Get the current time in UTC
        now_utc = datetime.now(pytz.utc)

        # https://www.cisa.gov/known-exploited-vulnerabilities-catalog
        kev_data = utils.download_file(self.url, 'data/known_exploited_vulnerabilities.json', logger=self.logger)
        kev_data_dict = json.loads(kev_data)

        # "catalogVersion": "2024.07.23",
        # "dateReleased": "2024-07-23T14:01:05.1793Z",
        source_last_update = parser.isoparse(kev_data_dict['dateReleased'])

        # Check if epss_status is available and its score_date
        if not cisa_status or cisa_status['source_last_update'].date() < source_last_update.date():

            # Log the number of exploits and size of the file
            num_cisa = len(kev_data_dict['vulnerabilities'])
            file_size = len(kev_data.encode('utf-8'))  # Size in bytes
            self.logger.info(f"[{chr(int('f14ba', 16))} CISA's Kev] Downloaded {num_cisa} exploits, file size: {file_size} bytes")

            # Initialize an empty list for the results
            results = []

            for vul in kev_data_dict['vulnerabilities']:
                # Append the data to results
                results.append({'id': vul['cveID'], 'kev':vul})

            # Log the number of CVE codes found
            self.logger.info(f"[{chr(int('f14ba', 16))} CISA's Kev] Total number of CVE codes found: {num_cisa}")

            self.mongodb_handler.queue_request('cve', results, update=True, key_field='id')
            self.mongodb_handler.update_source_status('cisa', {'source_last_update':source_last_update})

        else:
            # Print a message if the current version is up-to-date
            self.logger.info(f"Skipping update, source_last_update: {cisa_status['source_last_update']}")
