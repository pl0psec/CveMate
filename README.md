# CVEmate

<img src="doc/cvemate.svg" alt="CVEmate Logo" width="200"/>

## Overview

CVEmate is a comprehensive vulnerability data aggregation and management tool that collects information from multiple security data sources and maintains it in a MongoDB database. It provides automated data collection, prioritization, and management capabilities.

## Features

- Collects vulnerability data from multiple sources:
  - National Vulnerability Database (NVD)
  - CISA Known Exploited Vulnerabilities
  - EPSS (Exploit Prediction Scoring System)
  - Exploit Database
  - Metasploit Database
  - Debian Security Tracker
  - RedHat Security Data
  - CVE.org
  - Common Weakness Enumeration (CWE)

- Automated scheduling of data updates
- Configurable update intervals
- Priority scoring system for vulnerabilities
- MongoDB storage backend
- Timezone-aware operations

## Installation

1. Clone the repository
2. Install requirements:
```bash
pip install -r requirements.txt
```
3. Copy `configuration.ini.template` to `configuration.ini` and configure as needed

## Configuration

The `configuration.ini` file contains all necessary configuration settings:

- MongoDB connection details
- Data source API keys and settings
- Update intervals
- Timezone settings
- Logging configuration

## Usage

### Basic Usage

Run the main script:
```bash
python main.py
```

### Command Line Options

The tool supports various command line arguments for different operations. Use `python main.py -h` for a complete list of options.

## Project Structure

```
├── datasources/          # Data source handlers
├── handlers/            # Core functionality handlers
├── doc/                # Documentation
├── configuration.ini.template
├── main.py
└── requirements.txt
```

## Data Sources

The tool integrates with multiple data sources through dedicated handlers:

- `nvd_handler.py`: National Vulnerability Database integration
- `cisa_handler.py`: CISA KEV database integration
- `epss_handler.py`: EPSS scoring integration
- `exploitdb_handler.py`: Exploit Database integration
- `metasploit_handler.py`: Metasploit module integration
- `cveorg_handler.py`: CVE.org data integration
- `cwe_handler.py`: CWE database integration
- `debian_handler.py`: Debian Security Tracker integration
- `redhat_handler.py`: RedHat Security Data integration

## Core Components

- `mongodb_handler.py`: Database operations and management
- `config_handler.py`: Configuration management
- `logger_handler.py`: Logging functionality
- `prioritizer_handler.py`: Vulnerability prioritization logic
- `colored_console_handler.py`: Colored console output
- `utils.py`: Utility functions

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## License

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.
