"""Exports local JSON reports atomically with cancellation and private permissions."""
import json
import os
from pathlib import Path
import tempfile
from .capture import CaptureError


def save_report(report, path, cancel=None):
    target=Path(path)
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=target.parent,
                                         prefix='.'+target.name+'.',suffix='.tmp',delete=False) as stream:
            temporary=stream.name
            for chunk in json.JSONEncoder(indent=2,ensure_ascii=True,allow_nan=False).iterencode(report):
                if cancel is not None and cancel.is_set():raise CaptureError('Export cancelled.')
                stream.write(chunk)
            stream.write('\n');stream.flush();os.fsync(stream.fileno())
        if cancel is not None and cancel.is_set():raise CaptureError('Export cancelled.')
        os.replace(temporary,target);temporary=None
    finally:
        if temporary is not None:
            try:os.unlink(temporary)
            except FileNotFoundError:pass
