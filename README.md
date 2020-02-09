# WirelessDiscoverCrackScan

## Introduction
WDCS utilizes known WiFi-related security tools (listed below) to automate the process of discovering wireless networks, cracking passwords and scanning them. It automatically selects targets and runs all attacks. However, the additional interactive mode is also available to allow users select targets manually. All results are collected in a local database, so cracked psks and scan results can be exported. In the case of unsuccessfully cracked networks, it is also possible to export relevant data and perform cracking on another machine with more complex dictionaries using included additional script. 

The techniques used in this project are also separately described in [this](https://mmmds.pl/wifi-cheatsheet/) cheatsheet.

## Usage

```
Wireless Discover Crack Scan (v0.1)
	mass automated wifi security tool
Usage:
	wdcs.py auto - start auto scan
	wdcs.py manual - start interactive scan
	wdcs.py export OUTPUT_DIR - export nmap, psk, dictionary, pmkid and handshakes to files (for cracking)
	wdcs.py psk ESSID PSK - add psk
	wdcs.py show - show all collected info
```

## Flow
The whole flow can be explained in the following steps:

1. Discover nearby wireless networks.
2. Automatically select target (applying an optional BSSID whitelist and comparing the last attack time).
3. If the network is not protected (open) or psk is already known, then go to STEP 11, else assume it's WPA/WPA2 protected.
4. If the network supports WPS, then run reaver (pixie dust attack and brute force), else go to STEP 6.
5. If psk was found, then go to step 11.
6. Use second wireless adapter to initiate a connection using a random password and listen for PMKID.
7. If PMKID was collected, then go to STEP 9.
8. Deauthenticate connected clients and listen for a 4-way handshake.
9. Run hashcat against collected PMKID/4-way handshake.
10. If psk wasn't cracked go to STEP 1 (select next network).
11. Connect to the network and scan it with nmap.

## Demo 
[video](https://drive.google.com/file/d/1v7qPzZwbZZZ2B_SS8dOHYkY7m7TDQgyX/view)

## Requirements

The project was developed and tested on Ubuntu 18.04 but I cannot see why it wouldn't work on Kali Linux or Parrot OS.
Following tools are required:
- aircrack-ng
- nmap
- [reaver](https://github.com/t6x/reaver-wps-fork-t6x)
- tshark
- [hcxpcaptool](https://github.com/ZerBea/hcxtools)
- macchanger

Two network interfaces are required to catch PMKID packets (but the second one doesn't need to support monitor mode). Other options work with just one interface.

## Configuration
Default configuration file is created automatically in `~/.wdcs/cfg.ini`.

## External cracking
If PMKID or 4-way handshake were collected but psk cracking was unsuccessful, the hashcat supported files (4-way handshake - `*.2500` and PMKID - `*.16800`) can be exported by invoking `wdcs.py export OUTPUT_DIR`. Additionally, `dict_TIMESTAMP.txt` file will appear, containing a dictionary generated from collected ESSIDs.

The additional script `additional/hashcat_crack.py` can be run on any machine (for example Windows PC with more powerful GPU). It will detect all available `*.2500` and `*.16800` files and will run hashcat to crack them using dictionaries loaded from the relative `dicts` directory (you can put there any dictionaries you like). It keeps track of processed files, so you can add more files and dictionaries with time and the script will handle it without repeating the cracking process unnecessarily.

Cracked passwords can be imported to the main tool by invoking `wdcs.py psk ESSID PSK`.

## TODO
The project is not in its final state. It may contain bugs and there are things which would be helpful but are not implemented:
- [ ] Support WEP cracking / connecting
- [ ] Detect hidden networks
- [ ] Custom scripts run after initiating a connection
