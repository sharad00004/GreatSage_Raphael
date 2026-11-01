#!/usr/bin/env python3
"""Builds the standalone Ubuntu release from application sources."""
import argparse
import ast
import gzip
import hashlib
from importlib.metadata import distribution,version
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from greatsage_raphael import __version__


def third_party(stage,work):
    destination=stage/'LICENSES';destination.mkdir()
    for name in ('pyinstaller','pyinstaller-hooks-contrib'):
        package=distribution(name)
        for entry in package.files:
            if 'licenses/' in str(entry):shutil.copy2(package.locate_file(entry),destination/(name+'-'+Path(entry).name))
    sources=set()
    def collect(value):
        if isinstance(value,(list,tuple)):
            if len(value)>=3 and isinstance(value[1],str) and value[-1] in ('BINARY','EXTENSION'):
                sources.add(value[1])
            for item in value:collect(item)
        elif isinstance(value,dict):
            for item in value.values():collect(item)
    for toc in work.rglob('Analysis-00.toc'):collect(ast.literal_eval(toc.read_text()))
    packages={'python3.12','tcl8.6','tk8.6'}
    for source in sources:
        candidates={source,str(Path(source).resolve())}
        if source.startswith('/lib/'):candidates.add('/usr'+source)
        for path in candidates:
            result=subprocess.run(['dpkg-query','-S',path],capture_output=True,text=True,check=False)
            if result.returncode==0:
                packages.update(line.split(': ',1)[0].split(':',1)[0] for line in result.stdout.splitlines());break
    copied=[]
    for name in sorted(packages):
        path=Path('/usr/share/doc')/name/'copyright'
        if path.is_file():shutil.copy2(path,destination/(name+'-copyright.txt'));copied.append(name)
    shutil.copy2(ROOT/'packaging/ARTWORK-NOTICE.txt',destination/'ARTWORK-NOTICE.txt')
    (stage/'share/THIRD_PARTY_NOTICES.txt').write_text(
        'Application runtime: offline packet-capture analysis.\n'
        'Frozen runtime: CPython standard library, Tcl/Tk, and the bundled Linux shared libraries.\n'
        f'Build tool: PyInstaller {version("pyinstaller")} and hooks {version("pyinstaller-hooks-contrib")}.\n'
        'PyInstaller and hooks license files and available Ubuntu component copyright/license notices are included in LICENSES/.\n'
        'No external service/API is used by the application.\n\n'
        'Ubuntu component notices: '+', '.join(copied)+'\n',encoding='utf-8')


def build_release(work):
    subprocess.run([sys.executable,'-m','PyInstaller','--noconfirm','--clean','--onedir',
        '--name','GreatSage_Raphael','--paths',str(ROOT),'--add-data',
        str(ROOT/'greatsage_raphael/assets')+':greatsage_raphael/assets',
        '--distpath',str(work/'frozen'),'--workpath',str(work/'work'),
        '--specpath',str(work/'spec'),str(ROOT/'packaging/entry.py')],check=True)
    release_name=f'GreatSage_Raphael-{__version__}-linux-x86_64'
    stage=work/'release'/release_name;stage.mkdir(parents=True)
    shutil.copytree(work/'frozen/GreatSage_Raphael',stage/'app',symlinks=True)
    for path in (stage/'app').rglob('*'):
        if path.is_file() and path.name.casefold().startswith('readme'):path.unlink()
    share=stage/'share';share.mkdir()
    shutil.copy2(ROOT/'greatsage_raphael/assets/greatsage-raphael.png',share/'icon.png')
    for name in ('install.sh','uninstall.sh'):
        shutil.copy2(ROOT/'packaging'/name,stage/name);(stage/name).chmod(0o755)
    third_party(stage,work/'work')
    files={}
    for path in sorted(stage.rglob('*')):
        if path.is_symlink() and not path.resolve().is_relative_to(stage.resolve()):
            raise ValueError('External symbolic link in application bundle.')
        if path.is_file():files[path.relative_to(stage).as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    (stage/'BUILD-MANIFEST.json').write_text(json.dumps({'format':1,'product':'GreatSage_Raphael',
        'version':__version__,'target':'Ubuntu 24.04+ x86_64','minimum_glibc':'2.39',
        'python_version':platform.python_version(),'pyinstaller':version('pyinstaller'),'files':files},indent=2)+'\n')
    output=ROOT/'dist';output.mkdir(exist_ok=True)
    archive=output/(release_name+'.tar.gz')
    def normalize(info):
        info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0;return info
    with archive.open('wb') as destination:
        with gzip.GzipFile(filename='',mode='wb',fileobj=destination,mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w') as tar:tar.add(stage,arcname=release_name,filter=normalize)
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix('.gz.sha256').write_text(digest+'  '+archive.name+'\n')
    print(f'Release: {archive}\nSHA-256: {digest}\nSize: {archive.stat().st_size} bytes')


def main():
    parser=argparse.ArgumentParser(description='Builds the standalone Ubuntu application.')
    parser.add_argument('--work-dir',type=Path,help='Parent directory for temporary build files')
    args=parser.parse_args()
    if platform.system()!='Linux' or platform.machine()!='x86_64' or platform.libc_ver()[1]!='2.39':
        raise SystemExit('This release target requires an Ubuntu 24.04 x86-64 build environment.')
    if not re.fullmatch(r'\d+\.\d+\.\d+',__version__):raise SystemExit('Invalid application version.')
    if args.work_dir:args.work_dir.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='greatsage-build-',dir=args.work_dir) as temporary:
        build_release(Path(temporary))


if __name__=='__main__':main()
