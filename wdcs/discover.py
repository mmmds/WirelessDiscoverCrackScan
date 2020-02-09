import csv
from wdcs.ap import *
from wdcs.crack import *
from wdcs.basicutils import Logger


class Discover(object):

    def __init__(self, config, database, crack_utils, file_manager):
        self.config = config
        self.db = database
        self.crack_utils = crack_utils
        self.file_manager = file_manager

    def select_accidentally_found_hs_and_pmkid(self, filepath, devices):
        pmkid_messages = self.crack_utils.count_pmkid_messages(filepath)
        msg = [set(), set(), set()] # [0] -> EAPOL Mesages 1, [1] -> EAPOL Messages 2, [2] -> EAPOL Messages 3
        lines = self.crack_utils.read_tshark(filepath, "eapol")
        Logger.log("Found {} accidental eapol messages".format(len(lines)))
        for line in lines:
            cols = line.split("\t")
            if len(cols) == 8:
                if "2 of 4" in cols[7]:
                    msg[1].add((Bssid.normalize_bssid(cols[4]), Bssid.normalize_bssid(cols[2])))
                elif "1 of 4" in cols[7]:
                    msg[0].add((Bssid.normalize_bssid(cols[2]), Bssid.normalize_bssid(cols[4])))
                elif "3 of 4" in cols[7]:
                    msg[2].add((Bssid.normalize_bssid(cols[2]), Bssid.normalize_bssid(cols[4])))
        pmkid_candidates = [m[0] for m in msg[0] if m[0] in pmkid_messages]
        Logger.log("PMKID messages: {}, msg: {}".format(pmkid_messages, msg))
        done = []
        for candidate in pmkid_candidates:
            aps = [ap for ap in devices if ap.bssid == candidate]
            if len(aps) > 0:
                ap = aps[0]
                if not ap.pmkid:
                    try:
                        self.crack_utils.convert_and_crack_pcap_pmkid(ap, filepath)
                    except CrackSuccess:
                        done.append(ap.bssid)
                        continue
                else:
                    Logger.log("{} already have PMKID".format(ap.bssid))
        for m in msg[1]:
            if (m in msg[0] or m in msg[2]) and m[0] not in done:
                candidate = m[1]
                aps = [ap for ap in devices if ap.bssid == candidate]
                if len(aps) > 0:
                    ap = aps[0]
                    if not ap.hs4:
                        try:
                            filtered_pcap = self.crack_utils.extract_ap_station_communication_from_pcap(filepath, Bssid.make_colon_bssid(m[0]), Bssid.make_colon_bssid(m[1]))
                            self.crack_utils.read_and_crack_handshake(ap, filtered_pcap, None)
                        except CrackSuccess:
                            pass
                    else:
                        Logger.log("{} already have 4hs".format(ap.bssid))

    def __is_ap_collected(self, available, d):
        return len([x for x in available["ap"] if x.bssid == d.bssid]) > 0

    def __is_station_collected(self, available, d):
        return len([x for x in available["station"] if x.mac == d.mac]) > 0

    def discover_networks(self, available, sleep_seconds):
        rounds = 0
        update_counter = 0
        sleep = 30
        if sleep_seconds != -1:
            round_limit = sleep_seconds / sleep
            step = 1
        else:
            round_limit = 1
            step = 0
        Logger.log("Start scanning (sleep {} sec)...".format(sleep_seconds))
        airodump = None
        try:
            airodump = AirodumpProcess(self.config.iface, self.file_manager)
            airodump.wait_for_files()
            while rounds < round_limit:
                try:
                    Logger.log("...scanning...")
                    time.sleep(sleep)
                except KeyboardInterrupt:
                    Logger.log("Interrupted by user")
                    rounds = round_limit
                pt = Process.start_process_pipe_stdout(
                    ["tshark", "-r", airodump.pcap_filepath, "-Y", "wps.wifi_protected_setup_state == 2",
                     "-T", "fields", "-e", "wlan.bssid"])
                r = Bssid.normalize_bssid(pt.communicate()[0].decode("utf-8"))
                wps_bssids = set(r.split("\n"))
                Logger.log("WPS: " + str(wps_bssids))
                with open(airodump.csv_filepath) as f:
                    f_csv = csv.reader(f, delimiter=",")
                    for line in f_csv:
                        if len(line) == 15:
                            if line[0] == "BSSID":
                                continue
                            d = Available_AP_Device(line, wps_bssids)
                            if update_counter == 0 or not self.__is_ap_collected(available, d):
                                new = self.db.update_ap_device(d)
                                if new:
                                    d.new = True
                            if not self.__is_ap_collected(available, d):
                                available["ap"].append(d)
                        elif len(line) == 7:
                            if line[0] == "Station MAC":
                                continue
                            d = Available_Station_Device(line)
                            if update_counter == 0 or not self.__is_station_collected(available, d):
                                self.db.update_station_device(d)
                            if not self.__is_station_collected(available, d):
                                available["station"].append(d)
                rounds += step
                update_counter = (update_counter + 1) % self.config.SQL_DEVICE_UPDATE_THRESHOLD
        except:
            Logger.log("Cannot discover networks! {}".format(traceback.format_exc()))
        finally:
            if airodump:
                airodump.kill()
                return airodump.pcap_filepath
