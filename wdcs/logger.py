import datetime
import logging
import os
import sys


class LoggerImpl(object):

    def __init__(self):
        filename = os.getenv("HOME") + "/.wdcs/log"
        stdout_handler = logging.StreamHandler(sys.stdout)
        file_handler = logging.FileHandler(filename)
        logging.basicConfig(handlers=[stdout_handler, file_handler], format="[%(asctime)s] %(message)s", level=logging.DEBUG)

    def log(self, text):
        logging.info(text)

    def print_nolog(self, text):
        print(text)


Logger = LoggerImpl()