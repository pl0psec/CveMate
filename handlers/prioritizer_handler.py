import time
import logging

from handlers.config_handler import ConfigHandler
from handlers.mongodb_handler import MongoDBHandler


class Prioritizer:
    def __init__(self, mongo_handler, config_file='configuration.ini', logger=None):

        self.banner = f"{chr(int('EAD3', 16))} {chr(int('f14ba', 16))} Prioritizer"

        config_handler = ConfigHandler(config_file)

        self.mongodb_handler = mongo_handler
        self.logger = logger or logging.getLogger()

        self.cvss_threshold = 6.0
        self.epss_threshold = 0.2
        self.batch_size = 500  # Can be adjusted based on requirements

    def determine_priority(self, doc):

        # FIXME: not working for CVE-2018-1000021
        # FIXME: update to select the primary CVSS rating

        # Default base score
        base_score = 0

        # Attempt to extract baseScore from cvssMetricV31, cvssMetricV30, or cvssMetricV2
        if 'cvssMetricV31' in doc.get('nvd', {}).get('metrics', {}):
            base_score = doc['nvd']['metrics']['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 0)
        elif 'cvssMetricV30' in doc.get('nvd', {}).get('metrics', {}):
            base_score = doc['nvd']['metrics']['cvssMetricV30'][0].get('cvssData', {}).get('baseScore', 0)
        elif 'cvssMetricV2' in doc.get('nvd', {}).get('metrics', {}):
            base_score = doc['nvd']['metrics']['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', 0)

        epss_score = float(doc.get('epss', {}).get('epss_score', 0))

        if 'kev' in doc:
            return 1
        if base_score >= self.cvss_threshold and epss_score >= self.epss_threshold:
            return 1
        if base_score >= self.cvss_threshold:
            return 2
        if epss_score >= self.epss_threshold:
            return 3
        return 4


    def update_priorities(self):
        start_time = time.time()

        prefixed_collection = self.mongodb_handler.prefix + 'cve'

        # Projection to fetch only necessary fields
        projection = {
            'kev': 1,
            'nvd.metrics.cvssMetricV31.cvssData.baseScore': 1,
            'epss.epss_score': 1
        }

        # Using cursor batching for efficient data retrieval
        cursor = self.mongodb_handler.db[prefixed_collection].find(
            {}, projection).batch_size(self.batch_size)

        batch_updates = []

        for doc in cursor:
            priority = self.determine_priority(doc)
            update = UpdateOne({'_id': doc['_id']}, {'$set': {'priority': priority}})

            batch_updates.append(update)

            if len(batch_updates) == self.batch_size:
                self.mongodb_handler.db[prefixed_collection].bulk_write(
                    batch_updates)
                batch_updates = []

        # Process any remaining updates
        if batch_updates:
            self.mongodb_handler.db[prefixed_collection].bulk_write(
                batch_updates)

        elapsed_time = time.time() - start_time
        self.logger.info(f"Update complete. Time taken: {elapsed_time:.2f} seconds.")
