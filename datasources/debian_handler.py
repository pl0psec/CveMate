import csv
import json
import os

import requests

from handlers import utils
from handlers.config_handler import ConfigHandler
from handlers.logger_handler import Logger
from handlers.mongodb_handler import MongoDBHandler


def singleton(cls):
    """Decorator that implements the Singleton pattern for a class.
    
    This decorator ensures that only one instance of the decorated class is created.
    Subsequent calls to create an instance will return the existing instance.
    
    Args:
        cls (type): The class to be decorated.
    
    Returns:
        function: A wrapper function that manages the singleton instance.
    
    """
    instances = {}

    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance


@singleton
class DebianHandler:

    def __init__(self, config_file='configuration.ini'):
        """Initialize the Debian security tracker data retrieval and storage system.
        
        Args:
            config_file (str, optional): Path to the configuration file. Defaults to 'configuration.ini'.
        
        Returns:
            None
        
        Raises:
            ConfigurationError: If there's an issue with reading or parsing the configuration file.
            MongoDBConnectionError: If there's a problem connecting to the MongoDB database.
        """
        self.banner = f"{chr(int('EAD3', 16))} {chr(int('E77D', 16))} Debian"

        config_handler = ConfigHandler(config_file)

        debian_config = config_handler.get_debian_config()
        self.url = debian_config.get(
            'url', 'https://security-tracker.debian.org/tracker/data/json')
        self.save_data = config_handler.get_boolean(
            'cvemate', 'save_data', False)

        mongodb_config = config_handler.get_mongodb_config()
        self.mongodb_handler = MongoDBHandler(
            mongodb_config['host'],
            mongodb_config['port'],
            mongodb_config['db'],
            mongodb_config['username'],
            mongodb_config['password'],
            mongodb_config['authdb'],
            mongodb_config['prefix'])

    def update(self):
        """Update the Debian CVE data in the MongoDB database.
        
        This method downloads Debian CVE data from a specified URL, processes it, and updates the MongoDB database with the latest information. It also logs the total number of CVE codes found.
        
        Args:
            self: The instance of the class containing this method.
        
        Returns:
            list: A list of dictionaries containing the updated CVE data. Each dictionary has 'id' and 'data' keys, where 'id' is the CVE ID and 'data' contains the Debian-specific CVE details.
        
        Raises:
            JSONDecodeError: If the downloaded data is not valid JSON.
            ConnectionError: If there's an issue downloading the file from the URL.
        """
        print('\n'+self.banner)

        # Call the new download_file method
        json_data = utils.download_file(self.url, 'data/debian.json' if self.save_data else None)

        # Parse the JSON data
        parsed_data = json.loads(json_data)

        # Prepare the new JSON data
        updated_data = []

        for package, cve_entries in parsed_data.items():
            for cve_id, cve_data in cve_entries.items():
                updated_item = {
                    'id': cve_id,
                    'data': {
                        'debian': {
                            'package': package,
                            'cve_details': cve_data
                        }
                    }
                }
                updated_data.append(updated_item)

        # utils.write2json("data/debian.mongo.json", updated_data)

        # Log the number of CVE codes found
        Logger.log(f"[{chr(int('E77D', 16))} Debian] Total number of CVE codes found: {len(updated_data)}", 'INFO')

        self.mongodb_handler.update_or_create_multiple_documents('cve', updated_data)
        self.mongodb_handler.update_status('debian')

        return updated_data
