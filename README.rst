.. raw:: html

    <img src="doc/cvemate.svg" alt="CVE-Mate Logo"/>

.. image:: https://img.shields.io/pypi/pyversions/tqdm.svg?logo=python&logoColor=white
   :target: https://pypi.org/project/tqdm
.. image:: https://img.shields.io/github/license/teuf/cvemate
   :alt: GitHub License

CveMate is a tool designed to replicate and maintain a comprehensive database of all CVE (Common Vulnerabilities and Exposures) entries, enhanced with additional information from a variety of security-related sources, into a local MongoDB database.

.. contents::
   :local:
   :depth: 2

Data sources
------------

CveMate currently utilizes the following sources for vulnerability data:

.. list-table:: 
   :widths: 20 60 20
   :header-rows: 1

   * - **Source**
     - **Description**
     - **Format**
   * - **NVD**
     - Fetches CVE data from the National Vulnerability Database. Using NVD Rest API v2.0.
     - `NVD_CVE 2.0 <https://nvd.nist.gov/developers/vulnerabilities>`_
   * - **CVE.org**
     - Fetches CVE data from CVE.org. Using CVE JSON 5.0 format.
     - `CVE_RECORD 5.0 <https://github.com/CVEProject/cvelistV5>`_
   * - **CWE**
     - Common Weakness Enumeration (CWE™) is a list of software and hardware weaknesses.

       ‼️ Current implementation only captures basic CWE details. 
       
       🆘 Improvement needed to capture full details. Help is welcome :)
     - `CWE v4.13 <https://cwe.mitre.org/data/downloads.html>`_
   * - **Exploit-DB**
     - Database of vulnerabilities and exploits.
     - `exploit-db <https://gitlab.com/exploit-database/exploitdb>`_
   * - **Metasploit**
     - The Metasploit Framework contains a suite of tools that you can use to test security vulnerabilities, enumerate networks, execute attacks, and evade detection.
     - `Metasploit-framework <https://docs.rapid7.com/metasploit/msf-overview>`_ 
   * - **EPSS**
     - Estimate of the probability of exploitation.
     - `EPSS <https://www.first.org/epss/data_stats>`_
   * - **Debian Security-tracker**
     - Bug database maintained by Debian's security team.
     - `Debian Security Bug Tracker <https://security-tracker.debian.org/tracker>`_


Plans are underway to further enrich the database by integrating additional sources such as the GitHub Advisory Database.

Any suggestion ?

Prerequisites
-------------

Before you begin, ensure your environment is set up:

1. **Create a Configuration File**
   Copy and edit the configuration file with your MongoDB details:

   .. code-block:: sh

       cp configuration.ini.template configuration.ini

2. **Install Dependencies**
   Install required Python packages for CveMate:

   .. code-block:: sh

       pip3 install -r requirements.txt

Populate CveMate
----------------

To initialize CveMate and create a local copy of the NVD CVE list, run:

.. code-block:: sh

    python3 main.py --init

This process may vary in duration based on your internet connection and data size.

Update CveMate
--------------

Keep your data up-to-date with scheduled updates. Set up a cron job as follows:

1. Edit your crontab file:

   .. code-block:: sh

       crontab -e

2. Add a line to run the update command regularly, e.g., daily at 3 AM:

   .. code-block::

       0 3 * * * /path/to/python3 /path/to/main.py --update

Contribution
------------

We welcome contributions! If you have ideas or want to add new features.
