from wdcs.basicutils import Bssid
from wdcs.logger import Logger
from wdcs.timeutils import TimeUtils


class AP_Device(object):

    def __init__(self, rows, new=False):
        self.bssid = rows[0]
        self.essid = rows[1]
        try:
            self.power = int(rows[2])
        except ValueError:
            Logger.log("Invalid power {} for AP {}".format(rows[2], self.bssid))
            pass
        self.channel = rows[3]
        self.enc = rows[4]
        self.first_seen = rows[5]
        self.last_seen = rows[6]
        self.psk = rows[7]
        self.hs4 = rows[8]
        self.pmkid = rows[9]
        self.wps = rows[10]
        self.last_attack = rows[11] if rows[11] is not None else ""
        self.new = new
        self.status = rows[12] if rows[12] is not None else ""

    def __lt__(self, other):
        if other.power == "-1":
            return True
        if self.power == "-1":
            return False
        return self.power < other.power

    def __eq__(self, other):
        return self.power == other.power

    def merge(self, ap_device):
        self.power = ap_device.power
        self.channel = ap_device.channel
        self.last_seen = ap_device.last
        self.wps = ap_device.wps
        self.new = ap_device.new
        self.enc = ap_device.privacy

    def is_no_stations(self):
        return self.status == AP_Status.NO_STATIONS

    def __str__(self):
        return "AP device bssid={}, essid={}, channel={}, priv={}{}".format(self.bssid, self.essid, self.channel,
                                                                            self.enc, "(WPS)" if self.wps else "")


class Available_AP_Device(object):

    def __init__(self, csv, wps_bssids):
        self.bssid = Bssid.normalize_bssid(csv[0])
        self.first = TimeUtils.normalize_airodump_time(csv[1].strip())
        self.last = TimeUtils.normalize_airodump_time(csv[2].strip())
        self.channel = csv[3].strip()
        self.privacy = csv[5].strip()
        self.cipher = csv[6].strip()
        self.auth = csv[7].strip()
        self.power = csv[8].strip()
        self.essid = csv[13].strip()
        self.wps = self.bssid in wps_bssids
        self.new = False

    def __str__(self):
        return "AP device bssid={}, essid={}, channel={}, priv={}{}".format(self.bssid, self.essid, self.channel,
                                                                            self.privacy, "(WPS)" if self.wps else "")


class Available_Station_Device(object):

    def __init__(self, csv):
        self.mac = Bssid.normalize_bssid(csv[0])
        self.first = TimeUtils.normalize_airodump_time(csv[1].strip())
        self.last = TimeUtils.normalize_airodump_time(csv[2].strip())
        self.bssid = Bssid.normalize_bssid(csv[5])
        self.essid = csv[6].strip()

    def __str__(self):
        return "Station device mac={}, bssid={}, essid={}".format(self.mac, self.bssid, self.essid)


class AP_Status:
    NO_STATIONS = "NO_STATIONS"