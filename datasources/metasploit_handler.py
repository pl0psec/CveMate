import json

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
class MetasploitHandler:

    def __init__(self, config_file='configuration.ini'):
        self.banner = f"{chr(int('EAD3', 16))} {chr(int('eaaf', 16))} Metasploit"

        config_handler = ConfigHandler(config_file)
        metasploit_config = config_handler.get_config_section('metasploit')
        self.url = metasploit_config.get(
            'url', 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json')
        self.save_data = config_handler.get_boolean(
            'metasploit', 'save_data', False)

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
        json_data = utils.download_file(
            self.url, 'data/metasploit.json' if self.save_data else None)

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
                            'data': {
                                'metasploit':{ 'key': key,
                                'data': value}
                            }
                        }
                        # Add the dictionary to the array
                        updated_data.append(cve_dict)

        # Log the number of CVE codes found
        Logger.log(f"[{chr(int('eaaf', 16))} Metasploit] Total number of Exploit codes found: {len(updated_data)}", 'INFO')
        # print(updated_data)
        self.mongodb_handler.update_multiple_documents(
            'cve', updated_data)
        self.mongodb_handler.update_status('metasploit')

        return updated_data
