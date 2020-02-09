from wdcs import process
from wdcs.logger import Logger


class Hashcat(object):

    def __init__(self, config):
        self.config = config
        pass

    def crack_pmkid(self, filepath):
        return self.__crack(filepath, "16800")

    def crack_4hs(self, filepath):
        return self.__crack(filepath, "2500")

    def __crack(self, filepath, type):
        try:
            p = process.Process.start_process_stdout(["hashcat", "--force", "-a", "0", "-m", type, filepath, self.config.hashcat_dictionary])
            p.wait(300)
        except TimeoutError:
            Logger.log("hashcat takes too long.")
        finally:
            p.kill()
        return self.__check_result(filepath, type)

    def __check_result(self, filepath, type):
        p = process.Process.start_process_pipe(["hashcat", "--show", "-m", type, filepath])
        out = p.communicate()[0].decode("utf-8")
        try:
            return out.split("\n")[0].split(":")[-1]
        except IndexError:
            Logger.log("Invalid hashcat output: {}".format(out))
            return None
