import datetime
from wdcs.process import *
import re
from wdcs.logger import Logger


class Interface(object):

    @classmethod
    def check_monitor(cls, wlan_device):
        p = Process.start_process_pipe(["iwconfig", wlan_device])
        o = p.communicate()[0].decode("utf-8")
        mon = re.findall("Mode:Monitor", o)
        return len(mon) > 0

    @classmethod
    def change_mac(cls, wlan_device):
        Logger.log("changing MAC...")
        Process.start_process_pipe(["ifconfig", wlan_device, "down"]).wait()
        out = Process.start_process_pipe_stdout(["macchanger", "-r", wlan_device]).communicate()[0].decode("utf-8").split("\n")[-2]
        Logger.log(out)
        Process.start_process_pipe(["ifconfig", wlan_device, "up"]).wait()

    @classmethod
    def setup(cls, config):
        Logger.log("Checking monitor mode...")
        if Interface.check_monitor(config.iface):
            Logger.log("already in monitor")
        else:
            Logger.log("start monitor mode")
            Process.start_process_pipe(["ifconfig", config.iface, "down"])
            Process.start_process_pipe(["iwconfig", config.iface, "mode", "monitor"])
            Process.start_process_pipe(["ifconfig", config.iface, "up"])
            if Interface.check_monitor(config.iface):
                Logger.log("successfully switched to monitor")
            else:
                Logger.log("failed in switching to monitor")
        Interface.change_mac(config.iface)


class Bssid(object):

    @classmethod
    def normalize_bssid(cls, bssid):
        return bssid.strip().replace(":", "").upper()

    @classmethod
    def make_colon_bssid(cls, b):
        return b[0:2] + ":" + b[2:4] + ":" + b[4:6] + ":" + b[6:8] + ":" + b[8:10] + ":" + b[10:12]

    @classmethod
    def is_bssid(cls, bssid):
        return len(bssid) == 12


class FileManager(object):

    def __init__(self):
        self.directory = os.getenv("HOME") + "/.wdcs"
        if not os.path.exists(self.directory):
            os.mkdir(self.directory)
            Logger.log("Creating app directory")
        elif os.path.exists(self.directory) and os.path.isfile(self.directory):
            pass #error
        elif os.path.exists(self.directory) and os.path.isdir(self.directory):
            Logger.log("App directory already exists")

    def filepath(self, filename):
        return self.directory + "/" + filename

    def filename(self, filepath):
        return filepath.split("/")[-1]