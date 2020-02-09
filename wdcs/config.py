import configparser
from wdcs.basicutils import Bssid
from wdcs.logger import Logger
import os


class Config(object):

    def __init__(self, file_manager):
        self.define_const()
        config_path = file_manager.filepath("cfg.ini")
        parser = configparser.ConfigParser()
        default = configparser.ConfigParser()
        script_dir = os.path.dirname(__file__)
        default["DEFAULT"] = {
            "wlan_interface": "wlan0",
            "wlan_client_interface": "wlan1",
            "ap_whitelist": "",
            "interactive": "true",
            "scan_default_sleep_seconds": 600,
            "auto_scan_device_threshold_minutes": 15,
            "hashcat_dictionary": script_dir + "/dict.txt",
            "skip_wps_bruteforce": "false",
            "skip_wps_pixie": "false",
            "skip_pmkid": "false",
            "skip_4hs": "false",
            "crack_in_auto_mode": "true"
        }
        if os.path.exists(config_path):
            Logger.log("Reading config from file")
            parser.read(config_path)
        else:
            Logger.log("Creating default config file")
            with open(config_path, "w") as f:
                default.write(f)
                parser = default
        self.interactive = self.__get_bool(parser,"interactive")
        self.__ap_whitelist = []
        self.scan_default_sleep_seconds = parser["DEFAULT"].getint("scan_default_sleep_seconds", default["DEFAULT"]["scan_default_sleep_seconds"])
        self.iface = parser["DEFAULT"]["wlan_interface"]
        self.iface_client = parser["DEFAULT"]["wlan_client_interface"]
        self.hashcat_dictionary = parser["DEFAULT"]["hashcat_dictionary"]
        self.skip_wps_bruteforce = self.__get_bool(parser,"skip_wps_bruteforce")
        self.skip_wps_pixie = self.__get_bool(parser,"skip_wps_pixie")
        self.skip_pmkid = self.__get_bool(parser,"skip_pmkid")
        self.skip_4hs = self.__get_bool(parser,"skip_4hs")
        self.auto_scan_device_threshold_minutes = parser["DEFAULT"].getint("auto_scan_device_threshold_minutes", default["DEFAULT"].getint("auto_scan_device_threshold_minutes"))
        self.crack_in_auto_mode = self.__get_bool(parser, "crack_in_auto_mode")
        for ap in parser["DEFAULT"].get("ap_whitelist", "").split(","):
            bssid = Bssid.normalize_bssid(ap)
            if Bssid.is_bssid(bssid):
                self.__ap_whitelist.append(bssid)

    def __get_bool(self, parser, key):
        return parser["DEFAULT"].get(key, "").lower() in ["true", "yes", "1", "y"]

    def define_const(self):
        self.SQL_DEVICE_UPDATE_THRESHOLD = 10
        self.TRIES_PER_STATION = 3
        self.TRIES_LIMIT_NO_DEAUTH = 10
        self.DEAUTH_COUNT_BASE = 5
        self.SLEEP_AFTER_DEAUTH_BASE = 10
        self.SLEEP_NO_DEAUTH = 15

    def is_bssid_legal(self, bssid):
        if len(self.__ap_whitelist) > 0:
            return bssid in self.__ap_whitelist
        return True
