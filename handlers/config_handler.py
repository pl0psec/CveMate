import configparser
import os

def singleton(cls):
    instances = {}

    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance

@singleton
class ConfigHandler:
    def __init__(self, config_file='configuration.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.config.read(config_file)

    def get_cvemate_config(self):
        """ Retrieve the cvemate configuration. """
        return {k: v for k, v in self.config['cvemate'].items()}

    def get_mongodb_config(self):
        """ Retrieve the mongodb configuration, overwritten by env vars if defined. """
        mongodb_config = {
            'host': os.getenv('MONGODB_HOST', self.config['mongodb']['Host']),
            'port': os.getenv('MONGODB_PORT', self.config['mongodb']['Port']),
            'db': os.getenv('MONGODB_DB', self.config['mongodb']['DB']),
            'username': os.getenv('MONGODB_USERNAME', self.config['mongodb']['Username']),
            'password': os.getenv('MONGODB_PASSWORD', self.config['mongodb']['Password']),
            'authdb': os.getenv('MONGODB_AUTHDB', self.config['mongodb']['AuthDB']),
            'prefix': os.getenv('MONGODB_PREFIX', self.config['mongodb']['Prefix'])
        }
        return mongodb_config

    def get_nvd_config(self):
        """ Retrieve the nvd configuration. """
        return {k: v for k, v in self.config['nvd'].items()}

    def get_exploitdb_config(self):
        """ Retrieve the exploitdb configuration. """
        return {k: v for k, v in self.config['exploitdb'].items()}

    def get_epss_config(self):
        """ Retrieve the epss configuration. """
        return {k: v for k, v in self.config['epss'].items()}

    def get_debian_config(self):
        """ Retrieve the Debian configuration. """
        return {k: v for k, v in self.config['debian'].items()}

    def get_config_section(self, section):
        """ Retrieve a specific section from the configuration. """
        return {k: v for k, v in self.config[section].items()}

    def get_boolean(self, section, option, default=False):
        """ Get a boolean value from the configuration. """
        try:
            return self.config.getboolean(section, option)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default
