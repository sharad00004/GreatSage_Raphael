# GreatSage_Raphael

Developed for the **Cybersecurity Hackathon conducted by the Cybersecurity Club of the Indian Institute of Information Technology, Design and Manufacturing, Kancheepuram**.

**Team Name:** Inky Pinky Ponky

| Member | Roll Number |
|---|---|
| Sharad Kumar Dubey | CS23I1052 |
| Akash Patel | CS23I1055 |

GreatSage_Raphael is an offline desktop tool that analyzes packet captures and explains network faults and suspicious activity with likely causes, suggested fixes, and exact packet evidence.

## Project demo

[Watch the project demo on YouTube](https://youtu.be/AsdoMCevr6g).

## Download the standalone tool

**[Download for Ubuntu — GitHub Releases](https://github.com/sharad00004/GreatSage_Raphael/releases/latest)** · **[Public download page](https://sharad00004.github.io/GreatSage_Raphael/)**

For Ubuntu 24.04+ x86-64/amd64, download `GreatSage_Raphael-1.0.1-linux-x86_64.tar.gz` from the release assets. This archive includes Python, Tcl/Tk, and the application icon. Choose this application archive rather than GitHub's automatically generated source-code ZIP.

```bash
tar -xzf GreatSage_Raphael-1.0.1-linux-x86_64.tar.gz
cd GreatSage_Raphael-1.0.1-linux-x86_64
./install.sh --desktop
```

Launch **GreatSage_Raphael** from the application menu or desktop, or run `~/.local/bin/greatsage-raphael`. No sudo, pip, or internet connection is required after downloading the archive. Select **Open capture** to begin. The source and sample captures remain available below.

## Problem

Packet captures contain useful evidence, but interpreting them normally requires protocol knowledge and time. A failed connection might come from a closed service, a routing problem, an address conflict, or suspicious traffic. Students and small network teams need understandable explanations that distinguish observations from unproven attack claims.

## Solution

The application reads PCAP and PCAPNG files locally, decodes supported protocols, and applies original diagnosis rules. Each finding includes its category, severity, confidence, explanation, likely cause, suggested next step, and referenced packet numbers.

Selecting a finding filters the evidence table to its packets. Double-clicking a packet opens decoded metadata. Reports can be exported as JSON. The parser and detection logic do not wrap Wireshark or tshark output, and no external API receives capture data.

## Features

- **TCP:** connection resets, repeated payloads and overlapping sequence ranges, and possible port scans based on distinct destination ports within a time window.
- **DNS:** error responses, delayed responses, queries without observed replies, and conflicting address answers for the same transaction and question.
- **ARP and DHCP:** conflicting MAC claims for an IP address and multiple DHCP server identities, using DHCP option 54 where available.
- **ICMP and MTU:** IPv4/IPv6 destination-unreachable messages, quoted original endpoints, IPv4 fragmentation-needed feedback, and IPv6 Packet Too Big feedback.
- **Trusted inventory:** optional comparisons against approved ARP bindings, DHCP server identifiers, and DNS address records.
- **Desktop interface:** resizable panes, severity colors, decoded packet metadata, keyboard shortcuts, and cancellable background analysis.
- **Local report export:** atomic, cancellable JSON export with private file permissions and protection against overwriting the source capture.
- **Bounded input handling:** regular files only; 256 MiB file limit, 1 MiB record/block limit, 200,000 capture-record limit, and up to 1,000 finding groups. Truncation and unsupported input produce errors or analysis notes.

Supports Ethernet PCAP and enhanced-packet PCAPNG, IPv4/IPv6, TCP, UDP, ARP, DHCP, UDP DNS, ICMP/ICMPv6, and up to two VLAN tags.

## Setup and use

### Run from source

Requires Linux, **Python 3.10+**, and **Tkinter**. The source application uses only Python's standard library; no pip packages or API keys are required. Ubuntu 24.04 with Python 3.12 has been tested.

On Ubuntu, install the system packages if needed:

```bash
sudo apt install python3 python3-tk
```

From the project directory:

```bash
./launch.sh
```

To open a bundled example directly:

```bash
python3 -B -m greatsage_raphael --gui sample_captures/03_dns_issues.pcap
```

1. Select **Open capture** and choose a `.pcap` or `.pcapng` file.
2. Select a finding to view the explanation, likely cause, fix, and packet evidence.
3. Double-click a packet for decoded metadata, or select **Show all packets** to restore the capture list.
4. Select **Export JSON** to save a report locally.

**Ctrl+O** opens a capture, **Ctrl+S** exports a report, and **Esc** cancels the active operation.

Headless analysis prints JSON and does not require a display:

```bash
python3 -B -m greatsage_raphael sample_captures/05_mtu.pcap
```

An optional source desktop launcher can be installed with:

```bash
python3 install_desktop.py
```

### Standalone Ubuntu archive

The separately built standalone distribution targets **Ubuntu 24.04+ x86-64/amd64**, with glibc 2.39 or newer. Python, Tcl/Tk, and the application icon are bundled. A graphical desktop is required for the GUI; headless analysis works without a display.

Extract the standalone `.tar.gz`, open a terminal inside its extracted folder, and run:

```bash
./install.sh --desktop
```

No sudo, pip, or internet connection is required for standalone installation. Launch **GreatSage_Raphael** from the application menu or desktop, or run `~/.local/bin/greatsage-raphael`. After installation, the download folder is no longer needed. Uninstall with `~/.local/share/greatsage-raphael/uninstall.sh`.

## Sample captures

Sample capture files are available in [sample_captures/](sample_captures/).

**GUI:** Launch the application, select **Open capture**, and choose a file from `sample_captures/`. Select a finding to view its details and packet evidence.

A sample can also be opened directly in the GUI:

```bash
python3 -B -m greatsage_raphael --gui sample_captures/03_dns_issues.pcap
```

**Command line:** Run the following from the project directory to print the analysis as JSON:

```bash
python3 -B -m greatsage_raphael sample_captures/03_dns_issues.pcap
```

Replace the filename with any capture in `sample_captures/`.

## Libraries and tools used

| Component | Libraries or tools | Purpose |
|---|---|---|
| Application | Python standard library: `argparse`, `collections`, `dataclasses`, `hashlib`, `heapq`, `ipaddress`, `json`, `math`, `os`, `pathlib`, `queue`, `re`, `stat`, `struct`, `tempfile`, `threading` | Capture parsing, diagnosis, bounded processing, local reports, and UI support. |
| Desktop UI | `tkinter` / `ttk`, system Tcl/Tk | Widgets, file dialogs, packet tables, icon, and locally drawn interface graphics. |
| Standalone installer | Standard-library `contextlib`, `fcntl`, `shlex`, `shutil`, `subprocess`, `sys`, `uuid` | Per-account installation, integrity checks, update locking/rollback, launchers, and uninstall. |
| Standalone build only | PyInstaller 6.22.0, pyinstaller-hooks-contrib 2026.9, altgraph 0.17.5, packaging 26.3, setuptools 84.2.1 | Bundling the interpreter, Tcl/Tk, application modules, and required shared libraries. Versions are pinned in [packaging/build-requirements.txt](packaging/build-requirements.txt). |
| Lab capture preparation only | VirtualBox, OpenSSH, Wireshark `dumpcap`, `editcap`, `mergecap`, and Scapy | Authorized lab traffic, recording, extraction, merging, and format conversion. These tools are not required to run the application or read the included samples. |
| Isolated MTU lab only | Linux `iproute2`, network namespaces, ipvlan/veth, and `iptables` | A temporary router/link configuration that generated genuine MTU feedback. |

Wireshark `tshark` was used for independent packet-field checks; it is not called by the application. No external APIs or cloud analysis services are used. Required third-party runtime notices accompany the standalone archive.

## Scope and limitations

Findings distinguish network faults, possible attacks, and observations needing investigation. ARP conflicts, multiple DHCP identities, and conflicting DNS answers can have legitimate explanations. DNS hijacking and malicious intent are not proven by this tool. Zero findings does not establish network safety.

IP fragments are not reassembled. TCP/encrypted DNS, DNSSEC authenticity, CNAME-chain validation, IPv6 jumbograms, and scans distributed across many destination hosts are outside coverage. Checksums are not validated. Unsupported link types and legacy/simple PCAPNG packet blocks are rejected. The packet table displays the first 2000 packets unless filtered to finding evidence; analysis safety limits and skipped packets are reported explicitly.

Captures and exported reports contain network addresses and metadata. Testing and analysis should be limited to networks and files for which authorization exists.

## Artwork credits and disclaimer

The icon and visual inspiration reference *That Time I Got Reincarnated as a Slime* (*Tensura*), originally written by **Fuse**, with original light-novel illustrations by **Mitz Vah**, as credited by [Yen Press](https://yenpress.com/titles/9780316414203-that-time-i-got-reincarnated-as-a-slime-vol-1-light-novel).

The specific artist/source of the supplied masked-slime icon has not been verified; the series credits above are not a claim that either creator drew this exact image. Artwork and character rights remain with their respective creators and rights holders. No ownership of the franchise artwork, official affiliation, or endorsement is claimed. The interface's abstract geometric header is drawn locally in code.
