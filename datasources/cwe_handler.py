import re
import logging
import xml.etree.ElementTree as ET

from handlers import utils
from handlers.config_handler import ConfigHandler
from handlers.mongodb_handler import MongoDBHandler


def singleton(cls):
    instances = {}

    def get_instance(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return get_instance


@singleton
class CweHandler:

    def __init__(self, mongo_handler, config_file='configuration.ini', logger=None):
        self.logger = logger or logging.getLogger()
        self.banner = f"{chr(int('EAD3', 16))} {chr(int('eb83', 16))} CWE"

        self.mongodb_handler = mongo_handler

        config_handler = ConfigHandler(config_file)

        cwe_config = config_handler.get_config_section('cwe')
        self.url = cwe_config.get(
            'url', 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip')
        self.save_data = config_handler.get_boolean('cvemate', 'save_data', False)

        self.logger = logger or logging.getLogger()

    def strip_namespace(self, tag):
        """ Strip the namespace URI and return the local part of the tag """
        return tag[tag.find('}')+1:] if '}' in tag else tag

    def get_element_text(self, element):
        """ Recursively get the text content of an element, including nested elements """
        text = ''
        if element.text:
            text += element.text.strip()
        for child in element:
            text += self.get_element_text(child)
            if child.tail:
                text += child.tail.strip()
        return text

    def xhtml_to_html(self, text):
        """ Convert XHTML tags (including self-closing tags) to HTML tags """
        return re.sub(r'<\/?xhtml:([a-zA-Z]+)(\/?)>',
                    lambda m: f'<{m.group(1)}{" />" if m.group(2) else ">"}', text)


    def xml2json(self, xml_data):
        try:
            # Parse the XML data
            root = ET.fromstring(xml_data)

            # Initialize a list to hold all weaknesses
            weaknesses_list = []

            # Iterate over each Weakness element
            for weakness in root.findall('.//{http://cwe.mitre.org/cwe-7}Weakness'):
                # Initialize a dictionary for this weakness
                weakness_data = {}

                # Capture the attributes of the Weakness element
                for attr, value in weakness.attrib.items():
                    weakness_data[self.strip_namespace(attr)] = value

                # Iterate over all child elements of the Weakness element
                for child in weakness:
                    tag = self.strip_namespace(child.tag)

                    # Special handling for Related_Weaknesses
                    if tag == 'Related_Weaknesses':
                        related_weaknesses = []
                        for rel_weak in child.findall('{http://cwe.mitre.org/cwe-7}Related_Weakness'):
                            related_weakness = {
                                'id': rel_weak.get('CWE_ID'),
                                'nature': rel_weak.get('Nature')
                            }
                            related_weaknesses.append(related_weakness)
                        weakness_data['Related_Weaknesses'] = related_weaknesses
                    else:
                        text = self.get_element_text(child)
                        weakness_data[tag] = self.xhtml_to_html(text)

                # Add this weakness data to the list
                weaknesses_list.append(weakness_data)

            return weaknesses_list

        except ET.ParseError as e:
            print(f"XML parsing error: {e}")
            return []

    def init(self):
        print('\n'+self.banner)

        # Call the new download_file method
        xml_data = utils.download_file(self.url, 'data/cwec_latest.xml', logger=self.logger)

        json_data = self.xml2json(xml_data)
        # print(json_data[-1])

        if json_data:
            self.mongodb_handler.queue_request('cwe', json_data, update=True, key_field='ID')

        self.mongodb_handler.update_status('cwe')
