from wdcs.logger import Logger
import subprocess
import os
from wdcs import timeutils
import time


class Process(object):

    @classmethod
    def start_process_pipe(cls, cmd):
        return Process.start_process(cmd, subprocess.PIPE, subprocess.STDOUT)

    @classmethod
    def start_process_pipe_stdout(cls, cmd):
        return Process.start_process(cmd, subprocess.PIPE, subprocess.DEVNULL)

    @classmethod
    def start_process_devnull(cls, cmd):
        return Process.start_process(cmd, subprocess.DEVNULL, subprocess.DEVNULL)

    @classmethod
    def start_process_stdout(cls, cmd):
        return Process.start_process(cmd, None, None)

    @classmethod
    def start_process_shell(cls, cmd):
        return Process.start_process(cmd, None, None, True)

    @classmethod
    def start_process(cls, cmd, stdout, stderr, shell=False):
        Logger.log("Executing cmd: {}".format(cmd))
        return subprocess.Popen(cmd, stdout=stdout, stderr=stderr, shell=shell)


class AirodumpProcess(Process):

        def __init__(self, interface, file_manager, ap=None):
            self.file_manager = file_manager
            self.__prepare_output_files()
            cmd = ["airodump-ng", "--wps", "--output-format", "csv,pcap", "-w", self.file_manager.filepath("outa"), "--write-interval", "10"]
            if ap:
                cmd.append("--bssid")
                cmd.append(ap.bssid)
                cmd.append("-c")
                cmd.append(ap.channel)
            cmd.append(interface)
            self.p = Process.start_process_devnull(cmd)

        def __extract_last_file_number(self, ls_result, extension):
            x = [self.safe_int(x.replace("outa-", "").replace(extension, "")) for x in ls_result if
                 x.startswith("outa-") and x.endswith(extension)]
            x.sort(reverse=True)
            if len(x) > 0:
                return x[0]
            return 0

        def safe_int(self, val):
            try:
                return int(val)
            except:
                return 0

        def __prepare_output_files(self):
            pp = Process.start_process_pipe(["ls", self.file_manager.filepath(".")])
            ls_out = pp.communicate()[0].decode("utf-8").split("\n")
            csv_number = self.__extract_last_file_number(ls_out, ".csv")
            cap_number = self.__extract_last_file_number(ls_out, ".cap")
            if csv_number != cap_number:
                Logger.log("Something wrong with output files. CSV: {}, CAP: {}".format(csv_number, cap_number))
            new_number = csv_number + 1
            self.csv_filepath = self.file_manager.filepath("outa-{:02}.csv".format(new_number))
            self.pcap_filepath = self.file_manager.filepath("outa-{:02}.cap".format(new_number))

        def wait_for_files(self):
            Logger.log("Waiting for {} and {}".format(self.file_manager.filename(self.csv_filepath), self.file_manager.filename(self.pcap_filepath)))
            wait_limit = 10
            while not (os.path.exists(self.csv_filepath) and os.path.exists(self.pcap_filepath)):
                wait_limit -= 1
                if wait_limit == 0:
                    raise Exception("It's not gonna happen")
                time.sleep(5)
            Logger.log("Files exist")

        def kill(self):
            self.p.kill()


class WpaSupplicant(object):

    @classmethod
    def __write_config(cls, ap, r, file_manager):
        conf_file = file_manager.filepath("wpa_supplicant_{}.conf".format(ap.bssid))
        with open(conf_file, "w") as f:
            f.write(r)
        return conf_file

    @classmethod
    def __connect(cls, ap, config, file_manager, file_config_content, wait, second_iface):
        conf_file = cls.__write_config(ap, file_config_content, file_manager)
        iface = config.iface_client if second_iface else config.iface
        out_file = file_manager.filepath("out_wpa_supplicant")
        if os.path.isfile(out_file):
            os.remove(out_file)
        pw = Process.start_process_stdout(["wpa_supplicant", "-i", iface, "-c", conf_file, "-f",  out_file])
        if wait:
            tries = 0
            while tries < 5:
                tries += 1
                time.sleep(10)
                with open(out_file) as f:
                    if len([c for c in f.readlines() if "CTRL-EVENT-CONNECTED" in c]) > 0:
                        return pw
            raise Exception("Cannot connect using {}".format(conf_file))
        else:
            return pw

    @classmethod
    def connect_wpa(cls, ap, psk, config, file_manager, wait=False, second_iface=False):
        p = Process.start_process_pipe(["wpa_passphrase", "{}".format(ap.essid), psk])
        r = p.communicate()[0].decode("utf-8")
        return cls.__connect(ap, config, file_manager, r, wait, second_iface)

    @classmethod
    def connect_open(cls, ap, config, file_manager, wait=False):
        template = "network={{\n\tssid=\"{}\"\n\tkey_mgmt=NONE\n}}".format(ap.essid)
        return cls.__connect(ap, config, file_manager, template, wait, False)
