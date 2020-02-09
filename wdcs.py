import sys
from wdcs.wdcs import WDCS


def print_usage():
    bold = '\033[1m'
    end_bold = '\033[0m'
    print(bold + "Wireless Discover Crack Scan" +end_bold +" (v0.1)\n\tmass automated wifi security tool")
    print("Usage:"
        + "\n\t{}{} auto{} - start auto scan".format(bold, script_name, end_bold)
        + "\n\t{}{} manual{} - start interactive scan".format(bold, script_name, end_bold)
        + "\n\t{}{} export OUTPUT_DIR{} - export nmap, psk, dictionary, pmkid and handshakes to files (for cracking)".format(bold, script_name, end_bold)
        + "\n\t{}{} psk ESSID PSK{} - add psk".format(bold, script_name, end_bold)
        + "\n\t{}{} show{} - show all collected info".format(bold, script_name, end_bold)
          )


if __name__ == "__main__":
    args = len(sys.argv)
    script_name = sys.argv[0].split("/")[-1]
    if args == 2 and sys.argv[1] == "auto":
        WDCS().start(True)
    elif args == 2 and sys.argv[1] == "manual":
        WDCS().start(False)
    elif args == 3 and sys.argv[1] == "export":
        outdir = sys.argv[2]
        WDCS().export(outdir)
    elif args == 4 and sys.argv[1] == "psk":
        essid = sys.argv[2]
        psk = sys.argv[3]
        WDCS().add_psk(essid, psk)
    elif args == 2 and sys.argv[1] == "show":
        WDCS().print_all()
    else:
        print_usage()
