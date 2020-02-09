from wdcs.crack import WpaSupplicant
from wdcs.logger import Logger
from wdcs.process import Process
from wdcs import timeutils
import time


class Nmap(object):

    def __init__(self, config, db, file_manager):
        self.config = config
        self.db = db
        self.file_manager = file_manager

    def __start_nmap(self, ap, ip_cidr, udp, verbose=False):
        nmap = None
        try:
            scan_type = "-sU" if udp else "-sS"
            ports = "10" if udp else "100"
            name_suffix = "UDP" if udp else "TCP"
            if verbose:
                scan_type += "VC"
                name_suffix += "-V"
            out_file = self.file_manager.filepath("nmap_{}_{}".format(ap.bssid, name_suffix))
            cmd = ["nmap", "-oN", out_file, "-Pn", "-n", scan_type, "--top-ports", ports, "-e", self.config.iface]
            if verbose:
                cmd.append("-v")
            cmd.append(ip_cidr)
            nmap = Process.start_process_stdout(cmd)
            count = 0
            while True:
                count += 1
                time.sleep(30)
                if nmap.poll() is not None:
                    Logger.log("nmap done")
                    break
                if count >= 10:
                    Logger.log("nmap too long. stopping.")
                    break
            with open(out_file) as f:
                result = f.read()
                self.db.insert_scan_result(ap.bssid, result)
        finally:
            if nmap and nmap.poll() is not None:
                nmap.kill()

    def scan(self, ap):
        supplicant = None
        dhclient = None
        try:
            if ap.enc == "OPN":
                supplicant = WpaSupplicant.connect_open(ap, self.config, self.file_manager, wait=True)
            else:
                psk = self.db.select_psk_for_ap(ap)
                supplicant = WpaSupplicant.connect_wpa(ap, psk, self.config, self.file_manager, wait=True)
            dhclient = Process.start_process_pipe(["dhclient", "-r", self.config.iface])
            dhclient.wait(10)
            dhclient = Process.start_process_pipe(["dhclient", self.config.iface])
            dhclient.wait(10)
            ip = Process.start_process_pipe(["ip", "a", "show", self.config.iface])
            out = ip.communicate()[0].decode("utf-8")
            inet = [line for line in out.split("\n") if "inet " in line]
            if len(inet) > 0:
                Logger.log(inet[0])
                ip_cidr = inet[0].split()[1]
                self.__start_nmap(ap, ip_cidr, udp=False)
                self.__start_nmap(ap, ip_cidr, udp=True)
                self.__start_nmap(ap, ip_cidr, udp=False, verbose=True)
            else:
                Logger.log("No connection")
        finally:
            if supplicant:
                supplicant.kill()
            if dhclient:
                dhclient.kill()
            dhclient = Process.start_process_pipe(["dhclient", "-r", self.config.iface])
            dhclient.wait(10)


