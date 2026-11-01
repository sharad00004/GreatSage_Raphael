#!/usr/bin/env python3
"""Installs the source application launcher and bundled icon."""
from pathlib import Path
import subprocess


def install():
    project=Path(__file__).resolve().parent
    launcher=project/'launch.sh'
    icon=project/'greatsage_raphael/assets/greatsage-raphael.png'
    # Desktop Entry Exec quoting differs from shell quoting.
    executable=str(launcher).replace('\\','\\\\').replace('"','\\"').replace('`','\\`').replace('$','\\$')
    entry='\n'.join([
        '[Desktop Entry]','Version=1.0','Type=Application','Name=GreatSage_Raphael',
        'Comment=Offline network diagnosis with packet evidence',f'Exec="{executable}"',
        f'Path={project}',f'Icon={icon}','Terminal=false','Categories=Network;',
        'StartupNotify=true','StartupWMClass=Greatsage_raphael','',
    ])
    applications=Path.home()/'.local/share/applications'
    applications.mkdir(parents=True,exist_ok=True)
    desktop=Path.home()/'Desktop'
    for target in (applications/'greatsage-raphael.desktop',desktop/'GreatSage_Raphael.desktop'):
        target.write_text(entry,encoding='utf-8');target.chmod(0o755)
        print(target)
    # Supported desktop environments use this metadata to trust the launcher.
    subprocess.run(['gio','set',str(desktop/'GreatSage_Raphael.desktop'),'metadata::trusted','true'],capture_output=True)
    subprocess.run(['update-desktop-database',str(applications)],capture_output=True)

if __name__=='__main__':install()
