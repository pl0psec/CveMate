import time
import logging

from handlers.config_handler import ConfigHandler
from handlers.mongodb_handler import MongoDBHandler


class Prioritizer:
    def __init__(self, mongo_handler, config_file='configuration.ini', logger=None):

        """Initialize the Prioritizer class.
        
        Args:
            mongo_handler (object): Handler for MongoDB operations.
            config_file (str, optional): Path to the configuration file. Defaults to 'configuration.ini'.
            logger (logging.Logger, optional): Logger object for logging. If not provided, a default logger will be created.
        
        Returns:
            None
        
        Attributes:
            banner (str): A string containing Unicode characters representing the Prioritizer banner.
            mongodb_handler (object): The MongoDB handler object for database operations.
            logger (logging.Logger): Logger object for logging operations.
            cvss_threshold (float): The CVSS (Common Vulnerability Scoring System) threshold, set to 6.0.
            epss_threshold (float): The EPSS (Exploit Prediction Scoring System) threshold, set to 0.2.
            batch_size (int): The batch size for processing, set to 500.
        """
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
        """Determine the priority of a vulnerability based on its CVSS score, EPSS score, and KEV status.
        
        Args:
            self: The instance of the class containing this method.
            doc (dict): A dictionary containing vulnerability information including CVSS metrics, EPSS score, and KEV status.
        
        Returns:
            int: The priority level of the vulnerability, where:
                1 = Highest priority (KEV or high CVSS and EPSS scores)
                2 = High priority (high CVSS score only)
                3 = Medium priority (high EPSS score only)
                4 = Low priority (below thresholds for both CVSS and EPSS)
        
        Raises:
            KeyError: If the expected keys are not present in the input dictionary.
            ValueError: If there's an error converting the EPSS score to float.
        
        Notes:
            - The method uses CVSS v3.1 score if available, then falls back to v3.0, and finally to v2.0.
            - There are two FIXME comments in the code that need to be addressed:
              1. The method is not working for CVE-2018-1000021
              2. The primary CVSS rating selection needs to be updated
        """
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
        """Updates the priorities of CVE documents in the MongoDB collection.
        
        This method retrieves CVE documents from the database, determines their priority based on
        certain criteria, and updates the documents with the calculated priority. It uses batch
        processing for efficient database operations.
        
        Args:
            self: The instance of the class containing this method.
        
        Returns:
            None: This method doesn't return anything, but it updates the database and logs the
            completion time.
        
        Raises:
            pymongo.errors.BulkWriteError: If there's an error during the bulk write operation.
            pymongo.errors.PyMongoError: For any other MongoDB-related errors.
        """
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
