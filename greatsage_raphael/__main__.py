import argparse
import json
from .analysis import inspect
from . import __version__

def main():
    parser=argparse.ArgumentParser(description='GreatSage_Raphael offline capture diagnosis')
    parser.add_argument('capture',nargs='?',help='Analyze this file as JSON without opening the desktop UI')
    parser.add_argument('--version',action='version',version=f'GreatSage_Raphael {__version__}')
    parser.add_argument('--gui',action='store_true',help='Open the desktop interface, optionally loading CAPTURE')
    distribution=parser.add_mutually_exclusive_group()
    distribution.add_argument('--install',action='store_true',help='Install a standalone release for the current user')
    distribution.add_argument('--uninstall',action='store_true',help='Remove the current user standalone installation')
    parser.add_argument('--desktop',action='store_true',help='Also create a desktop shortcut when installing')
    parser.add_argument('--inventory',help='Optional local trusted inventory JSON')
    args=parser.parse_args()
    if args.install or args.uninstall:
        from .distribution import install,uninstall
        try:
            if args.install:install(desktop=args.desktop)
            else:uninstall()
        except (OSError,ValueError,KeyError) as exc:parser.exit(1,f'Installation error: {exc}\n')
        return
    if args.desktop:parser.error('--desktop requires --install')
    inventory=None
    if args.inventory:
        from .inventory import load_inventory
        try: inventory=load_inventory(args.inventory)
        except (OSError,ValueError,TypeError) as exc: parser.exit(1,f'Inventory error: {exc}\n')
    if args.capture and not args.gui:
        try: print(json.dumps(inspect(args.capture,inventory=inventory),indent=2))
        except (OSError,ValueError) as exc: parser.exit(1,f'Capture error: {exc}\n')
    else:
        from .app import main as desktop
        desktop(inventory,args.capture if args.gui else None)
if __name__=='__main__': main()
