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
class DebianHandler:

    def __init__(self, config_file='configuration.ini'):
        self.banner = f"{chr(int('EAD3', 16))} {chr(int('E77D', 16))} Debian"

        config_handler = ConfigHandler(config_file)

        debian_config = config_handler.get_debian_config()
        self.url = debian_config.get(
            'url', 'https://security-tracker.debian.org/tracker/data/json')
        self.save_data = config_handler.get_boolean(
            'debian', 'save_data', False)

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
