# External cracking script, part of https://github.com/mmmds/WirelessDiscoverCrackScan
import datetime
import subprocess
import os

### CONFIGURATION
HASHCAT_DIR = "C:\\hashcat-5.1.0"
HASHCAT_EXE = "hashcat64.exe"

LOG_FILE = "crack_log.txt"
DICT_DIR = "./dicts"

def load_dict_list():
    for r,d,f in os.walk(DICT_DIR):
        return f

def parse_log():
    r = {}
    with open(LOG_FILE, "r") as f:
        for line in f.readlines():
            try:
                a = line.split("/")
                date = a[0]
                dict_file = a[1].strip()
                hash_file = a[2].split(".")[0].strip()
                r[(hash_file, dict_file)] = date
            except:
                pass
    return r

def append_log(file, dictionary):
    text = "{}/{}/{}".format(str(datetime.datetime.now()), dictionary, file)
    with open(LOG_FILE, "a") as f:
        f.write("\n" + text)

def read_files():
    result = ([],[])
    files = os.listdir(".")
    for f in files:
        if f.endswith(".16800"):
            result[0].append(f.split(".")[0])
        elif f.endswith(".2500"):
            result[1].append(f.split(".")[0])
    return result
    
def process(files, t, logs, dicts):
    for f in files:
        for d in dicts:
            if (f.split(".")[0], d) not in logs:
                print("\n\n######## {} {}\n\n".format(f, d))
                cwd = os.getcwd()
                subprocess.Popen([HASHCAT_DIR+ "\\" + HASHCAT_EXE, "-m", t, "{}\\{}.{}".format(cwd,f, t), "{}\\{}\\{}".format(cwd,DICT_DIR, d)], cwd = HASHCAT_DIR).wait()
                append_log(f, d)
            else:
                print("\n\n-----------{} {} in logs\n\n".format(f, d))
                
        
files = read_files()
logs = parse_log()
dicts = load_dict_list()
print(dicts)
print(files)
print(logs)

pmkid = files[0]
hs4 = files[1]

process(pmkid, "16800", logs, dicts)
process(hs4, "2500", logs, dicts)
