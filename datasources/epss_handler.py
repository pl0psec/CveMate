import csv
import json
import os

import requests

from handlers import utils
from handlers.config_handler import ConfigHandler
from handlers.logger_handler import Logger
from handlers.mongodb_handler import MongodbHandler

def singleton(cls):
    instances = {}

    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance

@singleton
class EpssHandler:

    def __init__(self, config_file='configuration.ini'):
        self.banner = f"{chr(int('EAD3', 16))} {chr(int('f14ba', 16))} EPSS"

        config_handler = ConfigHandler(config_file)

        epss_config = config_handler.get_epss_config()
        self.url = epss_config.get('url', 'https://epss.cyentia.com/epss_scores-current.csv.gz')
        self.save_data = config_handler.get_boolean('epss', 'save_data', False)

        mongodb_config = config_handler.get_mongodb_config()
        self.mongodb_handler = MongodbHandler(
            mongodb_config['host'],
            mongodb_config['port'],
            mongodb_config['db'],
            mongodb_config['username'],
            mongodb_config['password'],
            mongodb_config['authdb'],
            mongodb_config['prefix'])

    def update(self):
        print('\n'+self.banner)

        # Call the new download_file method
        csv_data = utils.download_file(self.url, 'data/epss.csv' if self.save_data else None)

        # Log the number of exploits and size of the file
        num_epss = len(csv_data.splitlines()) - 1  # Subtract 1 for the header row
        file_size = len(csv_data.encode('utf-8'))  # Size in bytes
        Logger.log(f"[{chr(int('f14ba', 16))} EPSS] Downloaded {num_epss} exploits, file size: {file_size} bytes", 'INFO')

        # Initialize an empty list for the results
        results = []

        # Initialize a counter for CVE codes
        cve_count = 0

        # Process the CSV data
        lines = csv_data.splitlines()

        # Skip the first line (metadata/comment)
        lines = lines[1:]

        reader = csv.DictReader(lines)

        for row in reader:
            # Extract data from each row
            cve_id = row['cve']
            epss_score = row['epss']
            percentile = row['percentile']

            # Append the data to results
            results.append({'id': cve_id, 'data': {'epss': {'epss_score': epss_score, 'percentile': percentile}}})
            cve_count += 1

        # Log the number of CVE codes found
        Logger.log(f"[{chr(int('f14ba', 16))} EPSS] Total number of CVE codes found: {cve_count}", 'INFO')

        self.mongodb_handler.update_multiple_documents('cve', results)
        self.mongodb_handler.update_status('epss')
        return results
