"""Installs and removes the standalone application for a local account."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import uuid

PRODUCT='GreatSage_Raphael'
MARKER='.greatsage-install.json'


def installation_root():
    return Path.home()/'.local/share/greatsage-raphael'


def _atomic_write(path,text,mode):
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=path.parent,delete=False) as stream:
            temporary=Path(stream.name);stream.write(text)
        temporary.chmod(mode);os.replace(temporary,path);temporary=None
    finally:
        if temporary is not None:temporary.unlink(missing_ok=True)


def _owned_root(root):
    if root.is_symlink():raise ValueError('Installation directory must not be a symbolic link.')
    try:marker=json.loads((root/MARKER).read_text())
    except (OSError,ValueError) as exc:raise ValueError('Refusing to replace/remove a directory not managed by GreatSage_Raphael.') from exc
    if marker.get('product')!=PRODUCT or marker.get('root')!=str(root):
        raise ValueError('Invalid installation ownership marker.')


def _desktop_quote(value):
    if any(c in value for c in '\n\r\0'):raise ValueError('Installation paths cannot contain newline or NUL characters.')
    value=value.replace('%','%%').replace('\\','\\\\').replace('"','\\"').replace('`','\\`').replace('$','\\$')
    return '"'+value+'"'


def _optional_command(args):
    if shutil.which(args[0]):subprocess.run(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)


def verify_archive(package):
    manifest=json.loads((package/'BUILD-MANIFEST.json').read_text())
    if manifest.get('product')!=PRODUCT or manifest.get('format')!=1:raise ValueError('Unsupported release manifest.')
    actual=set()
    for path in package.rglob('*'):
        if path.is_symlink() and (Path(os.readlink(path)).is_absolute() or not path.resolve().is_relative_to(package.resolve())):
            raise ValueError('Unsafe symbolic link in release.')
        if path.is_file() and path.name!='BUILD-MANIFEST.json':actual.add(path.relative_to(package).as_posix())
    if actual!=set(manifest['files']):raise ValueError('Release file list differs from the integrity manifest.')
    for name,digest in manifest['files'].items():
        relative=Path(name)
        if relative.is_absolute() or '..' in relative.parts:raise ValueError('Unsafe path in release manifest.')
        path=package/relative
        if not path.resolve().is_relative_to(package.resolve()):raise ValueError('Release contains an external symbolic link.')
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError('Release integrity check failed: '+name)
    for required in ('app/GreatSage_Raphael','share/icon.png','uninstall.sh'):
        if required not in manifest['files']:raise ValueError('Incomplete release: '+required)
    return manifest


@contextmanager
def _installation_lock():
    parent=installation_root().parent;parent.mkdir(parents=True,exist_ok=True)
    with (parent/'.greatsage-raphael.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        yield


def install(package=None,desktop=False):
    with _installation_lock():return _install(package,desktop)


def _install(package=None,desktop=False):
    if package is None:
        if not getattr(sys,'frozen',False):raise ValueError('Run install.sh from the standalone release archive.')
        package=Path(sys.executable).resolve().parent.parent
    package=Path(package).resolve();manifest=verify_archive(package)
    root=installation_root()
    if package==root.resolve():raise ValueError('This copy is already installed; use a freshly extracted release to update.')
    if root.exists():_owned_root(root)
    root.parent.mkdir(parents=True,exist_ok=True)
    backup=None;written=[];originals={}
    executable=root/'app/GreatSage_Raphael'
    applications=Path.home()/'.local/share/applications'
    wrapper=Path.home()/'.local/bin/greatsage-raphael'
    desktop_entry=applications/'greatsage-raphael.desktop'
    entry='\n'.join(('[Desktop Entry]','Version=1.0','Type=Application','Name=GreatSage_Raphael',
        'Comment=Offline network capture analysis',f'Exec={_desktop_quote(str(executable))} --gui',
        f'Icon={root}/share/icon.png','Terminal=false','Categories=Network;',
        'StartupNotify=true','StartupWMClass=Greatsage_raphael',f'X-GreatSage-Managed={root}',''))
    targets=[(wrapper,'#!/bin/sh\n# GreatSage_Raphael standalone launcher\nexec '+shlex.quote(str(executable))+' "$@"\n',0o755),(desktop_entry,entry,0o644)]
    if desktop:
        folder=Path.home()/'Desktop'
        if shutil.which('xdg-user-dir'):
            result=subprocess.run(['xdg-user-dir','DESKTOP'],capture_output=True,text=True,check=False)
            if result.returncode==0 and result.stdout.strip():folder=Path(result.stdout.strip())
        if not folder.resolve().is_relative_to(Path.home().resolve()):raise ValueError('Desktop shortcut must stay inside your home directory.')
        targets.append((folder/'GreatSage_Raphael.desktop',entry,0o755))
    if root.exists():
        previous=json.loads((root/MARKER).read_text())
        known={path for path,_,_ in targets}
        for name in previous.get('launchers',[]):
            path=Path(name)
            if path in known or path.name!='GreatSage_Raphael.desktop' or path.is_symlink():continue
            if path.parent.resolve().is_relative_to(Path.home().resolve()) and path.is_file():
                if f'X-GreatSage-Managed={root}' in path.read_text():targets.append((path,entry,0o755))
    stage=Path(tempfile.mkdtemp(prefix='.greatsage-stage-',dir=root.parent))
    try:
        for name in ('app','share','LICENSES'):
            shutil.copytree(package/name,stage/name,symlinks=True)
        for name in ('uninstall.sh','BUILD-MANIFEST.json'):
            shutil.copy2(package/name,stage/name)
        (stage/MARKER).write_text(json.dumps({'product':PRODUCT,'root':str(root),'version':manifest['version'],
            'launchers':[str(path) for path,_,_ in targets]},indent=2)+'\n')
        if root.exists():
            backup=root.parent/('.greatsage-backup-'+uuid.uuid4().hex);root.rename(backup)
        stage.rename(root)
        for path,text,mode in targets:
            if path.is_symlink():raise ValueError('Refusing to overwrite a symbolic-link launcher: '+str(path))
            originals[path]=(path.read_text(),path.stat().st_mode&0o777) if path.exists() else None
            _atomic_write(path,text,mode);written.append(path)
    except BaseException:
        for path in reversed(written):
            old=originals[path]
            if old is None:path.unlink(missing_ok=True)
            else:_atomic_write(path,*old)
        if not stage.exists() and root.exists():shutil.rmtree(root)
        if backup is not None and backup.exists():backup.rename(root)
        raise
    finally:
        if stage.exists():shutil.rmtree(stage)
    if backup is not None:shutil.rmtree(backup)
    _optional_command(['update-desktop-database',str(applications)])
    if desktop:_optional_command(['gio','set',str(targets[-1][0]),'metadata::trusted','true'])
    print(f'Installed {PRODUCT} {manifest["version"]} in {root}')
    print(f'Launch from the application menu, or run: {wrapper}')
    print(f'Uninstall: {root}/uninstall.sh')
    return root


def uninstall():
    with _installation_lock():_uninstall()


def _uninstall():
    root=installation_root()
    if not root.exists():print('GreatSage_Raphael is not installed.');return
    _owned_root(root)
    marker=json.loads((root/MARKER).read_text())
    home=Path.home().resolve()
    for name in marker.get('launchers',[]):
        path=Path(name)
        if not path.is_absolute() or not path.parent.resolve().is_relative_to(home) or path.is_symlink():continue
        if not path.is_file():continue
        text=path.read_text()
        if str(root) in text and ('X-GreatSage-Managed=' in text or '# GreatSage_Raphael standalone launcher' in text):path.unlink()
    shutil.rmtree(root)
    _optional_command(['update-desktop-database',str(Path.home()/'.local/share/applications')])
    print('GreatSage_Raphael uninstalled. Captures and reports outside the installation directory were preserved.')
