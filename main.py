"""This module is the main entry point for the CVE Data Handling Script."""
import argparse
import os
import time

from datasources.cveorg_handler import CveDotOrgHandler
from datasources.cwe_handler import CweHandler
from datasources.debian_handler import DebianHandler
from datasources.epss_handler import EpssHandler
from datasources.exploitdb_handler import ExploitdbHandler
from datasources.metasploit_handler import MetasploitHandler
from datasources.nvd_handler import NvdHandler
from datasources.cisa_handler import CisaHandler

from handlers.config_handler import ConfigHandler
from handlers.logger_handler import Logger
from handlers.mongodb_handler import MongodbHandler
from handlers.prioritizer_handler import Prioritizer


class WideFormatter(argparse.HelpFormatter):
    """Extend to 120 columns"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, max_help_position=120, **kwargs)

def parse_args():
    """Parse and return command line arguments."""
    parser = argparse.ArgumentParser(description='CVE Data Handling Script',
                                     formatter_class=WideFormatter)
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Set log level to DEBUG')
    parser.add_argument('-c', '--config', default='configuration.ini',
                        help='Specify a configuration file')
    parser.add_argument('--init', action='store_true',
                        help='Fetch all CVE data')
    parser.add_argument('--update', action='store_true',
                        help='Fetch updates for CVE data')
    return parser.parse_args(), parser


def main():
    """Main function to handle CVE data updates and initialization."""
    args, parser = parse_args()

    # Use the provided configuration file or default to 'configuration.ini'
    config_file = args.config
    config_handler = ConfigHandler(config_file)
    cvemate_config = config_handler.get_cvemate_config()
    save_data = config_handler.get_boolean('cvemate', 'save_data', False)

    if args.debug:
        Logger.set_max_log_level('DEBUG')
    else:
        Logger.set_max_log_level(cvemate_config.get('loglevel', 'INFO'))

    if save_data:
        output_directory = 'data'
        if not os.path.exists(output_directory):
            os.makedirs(output_directory)

    if args.update or args.init:
        start_time = time.time()

        # prioritizer = Prioritizer()
        # prioritizer.update_priorities()

        # exit()
        # Init or Updaet CVE from NVD
        nvd = NvdHandler()
        if args.init:
            # TODO: Drop table first https://github.com/pl0psec/CveMate/issues/5
            # Temporary - Start
            mongodb_config = config_handler.get_mongodb_config()
            mongodb_handler = MongodbHandler(
                mongodb_config['host'],
                mongodb_config['port'],
                mongodb_config['db'],
                mongodb_config['username'],
                mongodb_config['password'],
                mongodb_config['authdb'],
                mongodb_config['prefix'])
            
            mongodb_handler.drop('cve')
            mongodb_handler.drop('update_status')
            # Temporary - End

            nvd.download_all_data()

        elif args.update:
            nvd.get_updates()

        # Update CWE from cwe.mitre.org
        cwe = CweHandler()
        cwe.update()

        # Add missing CVE from CVE.org (Usually unconfirmed CVE)
        cveorg = CveDotOrgHandler()
        cveorg.update()
        # exit()

        # Add Debian Bug database
        debian = DebianHandler()
        debian.update()

        # Add Exploit-DB
        exploitdb = ExploitdbHandler()
        exploitdb.update()

        # Add Exploit-DB
        metasploit = MetasploitHandler()
        metasploit.update()

        # Add EPSS score
        epss = EpssHandler()
        epss.update()

        cisa = CisaHandler()
        cisa.init()

        # FIXME: run Prioritizer after each CVE update directly for better performance
        prioritizer = Prioritizer()
        prioritizer.update_priorities()

        end_time = time.time()
        elapsed_time = end_time - start_time
        Logger.log(f" {chr(int('f253', 16))} Execution completed in {elapsed_time:.2f} seconds.",
                   'INFO')

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
