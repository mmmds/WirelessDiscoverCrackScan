from wdcs.ap import *
import sqlite3


class Database(object):

    def __init__(self, file_manager):
        self.con = sqlite3.connect(file_manager.filepath("wifi.db"))
        self.__sql_init()

    def __sql_init(self):
        try:
            c = self.con.cursor()
            c.execute(
                "CREATE TABLE "
                "ap_devices("
                "bssid TEXT PRIMARY KEY,"
                "first_seen TEXT,"
                "last_seen TEXT,"
                "last_attack TEXT,"
                "power TEXT,"
                "channel TEXT,"
                "privacy TEXT,"
                "cipher TEXT, "
                "auth TEXT, "
                "essid TEXT, "
                "wps INT, "
                "psk TEXT, "
                "wps_pin TEXT, "
                "pmkid TEXT, "
                "wpa_handshake BLOB, "
                "status TEXT "
                ")")
            c.execute(
                "CREATE TABLE station_devices("
                "mac TEXT PRIMARY KEY, "
                "first_seen TEXT, "
                "last_seen TEXT, "
                "bssid TEXT, "
                "essid TEXT"
                ")")
            c.execute(
                "CREATE TABLE scan_results("
                "bssid TEXT, "
                "scan_date TEXT,"
                "content BLOB"
                ")"
            )
            self.con.commit()
        except:
            pass

    def update_station_device(self, device):
        c = self.con.cursor()
        c.execute("SELECT count(*) FROM station_devices WHERE mac = ?", (device.mac,))
        exists = c.fetchone()[0] != 0
        if exists:
            Logger.log("Updating {}".format(device))
            c.execute("UPDATE station_devices SET last_seen = ?, bssid = ?, essid = ? WHERE mac = ?",
                      (device.last, device.bssid, device.essid, device.mac))
            self.con.commit()
        else:
            Logger.log("Adding {}".format(device))
            c.execute("INSERT INTO station_devices (mac, first_seen, last_seen, bssid, essid) values (?, ?, ?, ?, ?)",
                      (device.mac, device.first, device.last, device.bssid, device.essid))
            self.con.commit()

    def update_ap_device(self, device):
        c = self.con.cursor()
        c.execute("SELECT count(*) FROM ap_devices WHERE bssid = ?", (device.bssid,))
        exists = c.fetchone()[0] != 0
        if exists:
            Logger.log("Updating " + str(device))
            c.execute("UPDATE ap_devices SET last_seen = ?, power = ?, channel = ?, wps = ? WHERE bssid = ?",
                      (device.last, device.power, device.channel, device.wps, device.bssid))
            self.con.commit()
            return False
        else:
            Logger.log("Adding " + str(device))
            c.execute(
                "INSERT INTO ap_devices "
                "(bssid, power, first_seen, last_seen, channel, privacy, cipher, auth, essid, wps) "
                "values (?,?,?,?,?,?,?,?,?,?)",
                (device.bssid, device.power, device.first, device.last, device.channel, device.privacy, device.cipher,
                 device.auth, device.essid, device.wps))
            self.con.commit()
            return True

    def update_ap_wps(self, ap, pin, psk):
        c = self.con.cursor()
        c.execute("UPDATE ap_devices SET wps_pin = ?, psk = ? WHERE bssid = ?", (pin, psk, ap.bssid))
        self.con.commit()

    def update_ap_pmkid(self, ap, pmkid):
        c = self.con.cursor()
        c.execute("UPDATE ap_devices SET pmkid = ? WHERE bssid = ?", (pmkid, ap.bssid))
        self.con.commit()

    def update_ap_wpa_handshake(self, ap, data):
        c = self.con.cursor()
        c.execute("UPDATE ap_devices SET wpa_handshake = ? WHERE bssid = ?", (data, ap.bssid))
        self.con.commit()

    def select_bssids_with_psk(self):
        c = self.con.cursor()
        c.execute("SELECT bssid FROM ap_devices WHERE psk IS NOT NULL")
        rows = c.fetchall()
        rows = [r[0] for r in rows]
        return rows

    def select_bssids_with_pmkid_or_4hs(self):
        c = self.con.cursor()
        c.execute("SELECT bssid FROM ap_devices WHERE pmkid IS NOT NULL OR wpa_handshake IS NOT NULL")
        rows = c.fetchall()
        rows = [r[0] for r in rows]
        return rows

    def select_psk_for_ap(self, ap):
        c = self.con.cursor()
        c.execute("SELECT psk FROM ap_devices WHERE bssid = ?", (ap.bssid,))
        rows = c.fetchall()
        if len(rows) > 0:
            return rows[0][0]
        else:
            return None

    def select_psk_for_essid(self, essid):
        c = self.con.cursor()
        c.execute("SELECT psk FROM ap_devices WHERE essid = ?", (essid,))
        rows = c.fetchall()
        return rows

    def check_essid_exists(self, essid):
        c = self.con.cursor()
        c.execute("SELECT count(*) FROM ap_devices WHERE essid = ?", (essid,))
        row = c.fetchone()
        number = row[0]
        if number == 0:
            return False
        elif number == 1:
            return True
        else:
            Logger.log("There's more than one {}".format(essid))
            return True

    def get_display_devices(self, bssids = None):
        c = self.con.cursor()
        if bssids:
            c.execute("SELECT bssid, essid, power, channel, privacy, first_seen, last_seen, "
                      "psk is not null, wpa_handshake is not null, pmkid is not null, wps, last_attack, status "
                      "FROM ap_devices WHERE bssid IN ({})".format(",".join("?"*len(bssids))), bssids)
        else:
            c.execute("SELECT bssid, essid, power, channel, privacy, first_seen, last_seen, "
                      "psk is not null, wpa_handshake is not null, pmkid is not null, wps, last_attack, status "
                      "FROM ap_devices")
        rows = c.fetchall()
        return [AP_Device(r) for r in rows]

    def insert_scan_result(self, bssid, scan):
        c = self.con.cursor()
        c.execute("INSERT INTO scan_results (bssid, scan_date, content) VALUES (?,?,?)", (bssid, TimeUtils.now_str(), scan))
        self.con.commit()

    def update_last_attack(self, bssid, status = ""):
        time = TimeUtils.now_str()
        c = self.con.cursor()
        c.execute("UPDATE ap_devices SET last_attack = ?, status = ? WHERE bssid = ?", (time, status, bssid))
        self.con.commit()

    def get_4hs_and_pmkid(self):
        c = self.con.cursor()
        c.execute("SELECT bssid, pmkid, wpa_handshake, essid FROM ap_devices WHERE psk IS NULL AND (pmkid IS NOT NULL OR wpa_handshake IS NOT NULL)")
        rows = c.fetchall()
        return rows

    def update_psk_for_essid(self, essid, psk):
        c = self.con.cursor()
        c.execute("UPDATE ap_devices SET psk = ? WHERE essid = ?", (psk, essid))
        self.con.commit()

    def update_psk_for_bssid(self, bssid, psk):
        c = self.con.cursor()
        c.execute("UPDATE ap_devices SET psk = ? WHERE bssid = ?", (psk, bssid))
        self.con.commit()

    def select_all_psk(self):
        c = self.con.cursor()
        c.execute("SELECT bssid, essid, psk FROM ap_devices WHERE psk IS NOT NULL")
        rows = c.fetchall()
        return rows

    def get_nmap_results(self):
        c = self.con.cursor()
        c.execute("SELECT bssid, content FROM scan_results")
        rows = c.fetchall()
        return rows




