import json
import logging
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
class MetasploitHandler:

    LOG_PREFIX = f"[{chr(int('eaaf', 16))} Metasploit]"

    def __init__(self, mongo_handler, config_file='configuration.ini', logger=None):
        config_handler = ConfigHandler(config_file)
        metasploit_config = config_handler.get_config_section('metasploit')
        self.url = metasploit_config.get(
            'url', 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json')
        self.save_data = config_handler.get_boolean(
            'cvemate', 'save_data', False)

        self.mongodb_handler = mongo_handler
        self.logger = logger.bind(prefix=self.LOG_PREFIX) if logger else logger.bind(prefix=self.LOG_PREFIX)

    def init(self):
        metasploit_status = self.mongodb_handler.get_source_status('metasploit')
        try:
            latest_commit_date = utils.get_github_latest_commit_date(
                'https://api.github.com',
                'rapid7',
                'metasploit-framework',
                'db/modules_metadata_base.json'
            )
            self.logger.info(f"Latest commit date for 'db/modules_metadata_base.json': {latest_commit_date}")
        except GitHubAPIError as e:
            self.logger.error(e)

        # Convert last_git_commit to a date object
        latest_commit_date = parser.isoparse(latest_commit_date).date()

        # Check if exploitdb_status is available and its last_git_commit
        if not metasploit_status or parser.isoparse(metasploit_status['source_last_update']).date() < latest_commit_date:

            # Call the new download_file method
            json_data = utils.download_file(self.url, save_path='data/metasploit.json' if self.save_data else None, logger=self.logger)

            # Convert the JSON string to a Python dictionary
            json_dict = json.loads(json_data)

            # Initialize an array to hold the extracted data
            updated_data = []

            # Iterate through the items in the dictionary
            for key, value in json_dict.items():
                if 'references' in value:
                    for reference in value['references']:
                        if reference.startswith('CVE-'):
                            # Construct a new dictionary for each CVE
                            cve_dict = {
                                'id': reference,
                                'metasploit':{ 'key': key, 'data': value}
                            }
                            # Add the dictionary to the array
                            updated_data.append(cve_dict)

            # Log the number of CVE codes found
            self.logger.info(f"Total number of Exploit codes found: {len(updated_data)}")

            result = self.mongodb_handler.queue_request('cve', updated_data)
            self.logger.info(f"mongodb query: {result}")

            self.mongodb_handler.update_source_status('metasploit', {'source_last_update':latest_commit_date.isoformat()})

        else:
            # Skip if the condition is not met
            self.logger.info(f"Skipping update, source_last_update: {metasploit_status['source_last_update']}")
