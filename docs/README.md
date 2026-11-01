# Download and install GreatSage_Raphael

The public download page is **https://sharad00004.github.io/GreatSage_Raphael/**.

1. Open [GitHub Releases](https://github.com/sharad00004/GreatSage_Raphael/releases/latest).
2. Download `GreatSage_Raphael-1.0.1-linux-x86_64.tar.gz` and, optionally, its `.sha256` checksum. Choose the application archive, not the automatically generated source-code ZIP.
3. Extract the archive and open a terminal inside the extracted folder.
4. Run `./install.sh --desktop` without sudo.
5. Launch **GreatSage_Raphael** from the application menu or desktop, or run `~/.local/bin/greatsage-raphael`.

The standalone build targets Ubuntu 24.04+ x86-64/amd64 with glibc 2.39+. Python, Tcl/Tk, and the icon are included. Installation and analysis work offline after downloading the archive. A graphical desktop is needed for the GUI.

Select **Open capture** to load a PCAP/PCAPNG file. Sample files are available in the repository's [sample_captures](../sample_captures/) folder. The [main README](../README.md) describes features, source setup, CLI usage, dependencies, limitations, and artwork credits.

To uninstall, run `~/.local/share/greatsage-raphael/uninstall.sh`. Reports and captures outside the installation directory are preserved.
