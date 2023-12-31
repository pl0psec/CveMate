import os
import argparse
import time

from handlers import utils

from handlers.logger_handler import Logger
from handlers.config_handler import ConfigHandler

from datasources.nvd_handler import NvdHandler
from datasources.exploitdb_handler import ExploitdbHandler


def parse_args():
    parser = argparse.ArgumentParser(description="CVE Data Handling Script")
    parser.add_argument("-d", "--debug", action="store_true", help="Set log level to DEBUG")
    parser.add_argument("--update", action="store_true", help="Fetch updates for CVE data")
    parser.add_argument("--init", action="store_true", help="Fetch all CVE data")
    return parser.parse_args(), parser

def main():
    args, parser = parse_args()
    config_handler = ConfigHandler('configuration.ini')
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
       
        nvd = NvdHandler()
        exploitdb = ExploitdbHandler()

        # if args.update:
        #     nvd.getUpdates(24, follow=False)
            
        # elif args.init:            
        #     nvd.getAllCVE(follow=False)
           
        # Update Exploit-DB
        exploitdb.update()

        end_time = time.time()
        elapsed_time = end_time - start_time
        Logger.log(f"Execution completed in {elapsed_time:.2f} seconds.", "INFO")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
