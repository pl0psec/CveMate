"""This module is the main entry point for the CVE Data Handling Script."""

import os
import argparse
import time

from handlers.logger_handler import Logger
from handlers.config_handler import ConfigHandler

from datasources.cwe_handler import CweHandler
from datasources.nvd_handler import NvdHandler
from datasources.cveorg_handler import CveDotOrgHandler
from datasources.exploitdb_handler import ExploitdbHandler
from datasources.metasploit_handler import MetasploitHandler
from datasources.epss_handler import EpssHandler
from datasources.debian_handler import DebianHandler

class WideFormatter(argparse.HelpFormatter):
    """Extend to 120 columns"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, max_help_position=120, **kwargs)

def parse_args():
    """Parse and return command line arguments."""
    parser = argparse.ArgumentParser(description="CVE Data Handling Script",
                                     formatter_class=WideFormatter)
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Set log level to DEBUG")
    parser.add_argument("-c", "--config", default="configuration.ini",
                        help="Specify a configuration file")
    parser.add_argument("--init", action="store_true",
                        help="Fetch all CVE data")
    parser.add_argument("--update", action="store_true",
                        help="Fetch updates for CVE data")
    return parser.parse_args(), parser


def main():
    """Main function to handle CVE data updates and initialization."""
    args, parser = parse_args()

    # Use the provided configuration file or default to 'configuration.ini'
    config_file = args.config
    config_handler = ConfigHandler(config_file)
    cvemate_config = config_handler.get_cvemate_config()

    if args.debug:
        Logger.set_max_log_level("DEBUG")
    else:
        Logger.set_max_log_level(cvemate_config.get('loglevel', 'INFO'))

    output_directory = "data"
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    if args.update or args.init:
        start_time = time.time()

        # Update CWE from cwe.mitre.org
        cwe = CweHandler()
        cwe.update()

        # Init or Updaet CVE from NVD
        nvd = NvdHandler()
        if args.init:
            nvd.download_all_data()

        elif args.update:
            nvd.get_updates(follow=False)

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

        end_time = time.time()
        elapsed_time = end_time - start_time
        Logger.log(f" {chr(int('f253', 16))} Execution completed in {elapsed_time:.2f} seconds.",
                   "INFO")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
