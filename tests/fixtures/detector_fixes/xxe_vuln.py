"""XXE fixtures — must be detected."""
import xml.etree.ElementTree as ET
from lxml import etree
from xml.dom import minidom


def parse_user_xml(user_input):
    root = ET.fromstring(user_input)
    return root


def parse_lxml(data):
    tree = etree.parse(data)
    return tree


def parse_minidom(xml_content):
    dom = minidom.parseString(xml_content)
    return dom
