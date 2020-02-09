#!/usr/bin/python3

from wdcs.config import Config
from wdcs.scan import *
from wdcs.database import *
from wdcs.discover import Discover
from wdcs.timeutils import TimeUtils
from wdcs.crack import *
from wdcs.hashcat import Hashcat
import itertools
import sys
import os


class StatusEnum:
    def __init__(self, scan, attack):
        self.scan = scan
        self.attack = attack


class Status:
    ALL = StatusEnum(True, True)
    NONE = StatusEnum(False, False)
    SCAN_ONLY = StatusEnum(True, False)
    ATTACK_ONLY = StatusEnum(False, True)


class WDCS(object):

    def __init__(self):
        self.file_manager = FileManager()
        self.db = Database(self.file_manager)
        self.config = Config(self.file_manager)
        self.hashcat = Hashcat(self.config)
        self.crack_utils = WpaCrackUtils(self.file_manager, self.db, self.hashcat)
        self.scanner = Discover(self.config, self.db, self.crack_utils, self.file_manager)
        self.wps_cracker = WpsCracker(self.config, self.file_manager, self.db)
        self.wpa_pmkid_cracker = WpaPmkidCracker(self.file_manager, self.crack_utils, self.config)
        self.wpa_handshake_cracker = WpaHandshakeCracker(self.config, self.crack_utils, self.file_manager)
        self.nmap = Nmap(self.config, self.db, self.file_manager)

    def get_display_merged_with_available(self, available_devices):
        available_bssids = [d.bssid for d in available_devices]
        display_devices = self.db.get_display_devices(available_bssids)
        converted = []
        i = len(display_devices)
        for av in available_devices:
            dds = [d for d in display_devices if d.bssid == av.bssid]
            if len(dds) > 0:
                dds[0].merge(av)
        display_devices.extend(converted)
        display_devices.sort()
        return display_devices

    def print_discovered_devices(self, available, devices):
        if len(devices) > 0:
            essid_length = str(max([len(d.essid) for d in devices]))
            enc_length = str(max([len(d.enc) for d in devices]))
            power_length = str(max([len(str(d.power)) for d in devices]))
            line_format = "{:<3}  {:<17}  {:<" + essid_length + "}  {:<" + power_length + "}  {:<2}  {:<" + enc_length + "}  {:<3}  {:<16}  {:<16}  {:<16}  {:<3}  {:<3}  {:<3}  {:<5} {}"
            print(line_format.format("NUM", "BSSID", "ESSID", "PWR", "CH", "ENC", "WPS", "FIRST SEEN", "LAST SEEN", "LAST ATTACK", "NEW", "PSK", "4HS", "PMKID", "CLIENTS..."))
            num = 0
            for d in devices:
                num += 1
                stations = "[{}]".format(",".join([ Bssid.make_colon_bssid(st.mac) for st in available["station"] if st.bssid == d.bssid ]))
                print(line_format.replace("<", ">").format(num, Bssid.make_colon_bssid(d.bssid), d.essid, d.power, d.channel, d.enc, d.wps, d.first_seen, d.last_seen, d.last_attack, d.new, d.psk, d.hs4, d.pmkid, stations))

    def export_nmap(self, outdir):
        if os.path.exists(outdir):
            Logger.log("Directory exists!")
            return
        os.mkdir(outdir)
        rows = self.db.get_nmap_results()
        for row in rows:
            content = row[1]
            scan_type = "TCP"
            if "-sSVC" in content[0:250]:
                scan_type = "TCP-V"
            elif "-sU" in content[0:250]:
                scan_type = "UDP"
            filename = "{}/nmap_{}_{}".format(outdir, row[0], scan_type)
            with open(filename, "w") as f:
                f.write(content)
                Logger.log("Written to {}".format(filename))

    def prepare_essid_dict(self, essids, outdir):
        all = set(essids)
        all.update(list(itertools.chain(*[e.split("-") for e in essids])))
        all.update(list(itertools.chain(*[e.split("_") for e in essids])))
        all.update(list(itertools.chain(*[e.split(" ") for e in essids])))
        all.update([e.lower() for e in all])
        all.update([e.upper() for e in all])
        temp = set()
        for a in all:
            for i in range(0,21):
                temp.add("{}{}".format(a,i))
            for i in range(2000,2022):
                temp.add("{}{}".format(a,i))
        all.update(temp)
        filename = outdir+"/dict_{}.txt".format(str(time.time()).split(".")[0])
        with open(filename, "w") as f:
            for a in all:
                f.write(a)
                f.write("\n")

    def export(self, outdir):
        if os.path.exists(outdir):
            Logger.log("Directory exists!")
            return
        os.mkdir(outdir)
        self.export_pmkid_4hs(outdir)
        self.export_psk(outdir)
        self.export_nmap(outdir + "/nmap")

    def export_pmkid_4hs(self, outdir):
        rows = self.db.get_4hs_and_pmkid()
        essids = [ r[3] for r in rows ]
        self.prepare_essid_dict(essids, outdir)
        for row in rows:
            bssid = row[0]
            pmkid = row[1]
            hs = row[2]
            if pmkid:
                suffix = "16800"
                data = pmkid
                option = "w"
            elif hs:
                suffix = "2500"
                data = hs
                option = "wb"
            else:
                pass
            filename = outdir+"/{}.{}".format(bssid, suffix)
            with open(filename, option) as f:
                f.write(data)
                Logger.log("Written to {}".format(filename))

    def export_psk(self, outdir):
        psks = self.db.select_all_psk()
        psk_data = "\n".join(["{}\t{}\t{}".format(r[0], r[1], r[2]) for r in psks]) + "\n"
        pskfile = outdir + "/psk.csv"
        with open(pskfile, "w") as f:
            f.write(psk_data)
            Logger.log("Exported PSK:\n" + psk_data)

    def add_psk(self, essid, psk):
        if self.db.check_essid_exists(essid):
            old_psk = self.db.select_psk_for_essid(essid)
            if len(old_psk) > 0:
                Logger.log("Changing psk for {}. From {} to {}".format(essid, old_psk, psk))
            else:
                Logger.log("Adding psk {} to {}".format(psk, essid))
            self.db.update_psk_for_essid(essid, psk)

    def run_nmap(self, ap):
        Logger.log("running nmap for ({})...".format(ap))
        self.nmap.scan(ap)

    def prepare_available(self):
        available = {"ap": [], "station": []}
        return available

    def is_ap_suitable_for_auto(self, d, available):
        return d.power != "-1" and self.config.is_bssid_legal(d.bssid) \
            and (self.config.crack_in_auto_mode or (d.psk or d.enc == "OPN")) \
            and (len(d.last_attack) == 0 or
                 (TimeUtils.calc_minutes_diff(TimeUtils.now(), TimeUtils.parse(d.last_attack)) > self.config.auto_scan_device_threshold_minutes)
                 or (d.is_no_stations() and len(self.get_stations_for_ap(d, available)) > 0))

    def get_stations_for_ap(self, ap, available):
        stations = [s.mac for s in available["station"] if
                    s.bssid == ap.bssid or s.essid == ap.essid]
        return stations

    def print_all(self):
        display_devices = self.db.get_display_devices()
        stations = {"station": []} # TODO
        self.print_discovered_devices(stations, display_devices)

    def start(self, auto=False):
        Interface.setup(self.config)
        status = Status.ALL
        discover_sleep = self.config.scan_default_sleep_seconds
        devices = None
        while True:
            try:
                if status.scan:
                    available = self.prepare_available()
                    Interface.change_mac(self.config.iface)
                    pcap = self.scanner.discover_networks(available, discover_sleep)
                    devices = self.get_display_merged_with_available(available["ap"])
                    if pcap:
                        self.scanner.select_accidentally_found_hs_and_pmkid(pcap, devices)
                    if not auto:
                        os.system("reset")
                    self.print_discovered_devices(available, devices)

                if auto:
                    index = 0
                    for d in devices:
                        if self.is_ap_suitable_for_auto(d, available):
                            break
                        index += 1
                    if 0 <= index < len(devices):
                        status = Status.ALL
                    else:
                        status = Status.SCAN_ONLY
                else:
                    command = input("Enter number to proceed attack, 'c' or 'c SECONDS' to continue scan (-1 is inf), 'q' to quit\n")
                    if command == "c":
                        status = Status.SCAN_ONLY
                    elif command.startswith("c"):
                        try:
                            if len(command.split(" ")) == 2:
                                discover_sleep = int(command.split(" ")[1])
                                status = Status.SCAN_ONLY
                        except:
                            pass
                    elif command == "q":
                        break
                    else:
                        try:
                            index = int(command) - 1
                            if index < 0 or index >= len(devices):
                                raise ValueError()
                            status = Status.ALL
                        except ValueError:
                            status = Status.NONE

                if status.attack:
                    ap = devices[index]
                    Logger.log("Selected {}".format(ap))
                    if not self.config.is_bssid_legal(ap.bssid):
                        status = Status.NONE
                        Logger.log("{} is not whitelisted".format(ap.bssid))
                        continue
                    ap.last_attack = self.db.update_last_attack(ap.bssid)
                    try:
                        if auto and not self.config.crack_in_auto_mode:
                            Logger.log("Skipping cracking")
                            pass
                        elif not (ap.psk or ap.hs4 or ap.pmkid):
                            Logger.log("Cracking...")
                            stations = self.get_stations_for_ap(ap, available)
                            Logger.log("{} wps={}, clients={}".format(str(ap), str(ap.wps), str(stations)))

                            if ap.wps and not ap.is_no_stations():
                                if not self.config.skip_wps_pixie:
                                    self.wps_cracker.crack(ap, pixie=True)
                                if not self.config.skip_wps_bruteforce:
                                    self.wps_cracker.crack(ap, pixie=False)

                            if "WPA" in ap.enc:
                                if not (ap.hs4 or ap.pmkid):
                                    if not self.config.skip_pmkid:
                                        self.wpa_pmkid_cracker.crack_wpa_pmkid(ap)
                                    if not self.config.skip_4hs and not ap.is_no_stations():
                                        self.wpa_handshake_cracker.crack_wpa_handshake(ap, stations, True)
                                else:
                                    Logger.log("Already have handshake/pmkid")

                            ap.last_attack = self.db.update_last_attack(ap.bssid)
                        elif ap.enc == "OPN":
                            Logger.log("Open network. Nothing to crack")
                        else:
                            Logger.log("Already have PSK")

                    except CrackSuccess:
                        Logger.log("Crack success!")
                        ap.last_attack = self.db.update_last_attack(ap.bssid)
                    except NoStations:
                        Logger.log("No stations") # do not update last attack
                        ap.last_attack = self.db.update_last_attack(ap.bssid, AP_Status.NO_STATIONS)

                    if ap.psk or ap.enc == "OPN":
                        ap.last_attack = self.db.update_last_attack(ap.bssid)
                        self.run_nmap(ap)
            except KeyboardInterrupt as e:
                raise e
            except:
                Logger.log("Something went wrong! {}".format(traceback.format_exc()))

