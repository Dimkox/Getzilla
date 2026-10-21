"""Example adapter. Engineering evidence, not legal advice.

Returned provenance is unsigned metadata, not embedded marking. C2PA needs a separately
configured trusted c2patool and signing identity. Publish only caller-approved public labels.
"""
from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404
import tempfile
from datetime import datetime, timezone
from pathlib import Path

AI_DISCLOSURE = 'You are interacting with an AI system.'
IPTC_GENERATED = 'http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia'


def mark_generated_content(content: bytes | str, *, generator: str, model: str,
                           media_type: str, path: str | None = None) -> dict:
    """Return original content and, on success, separate C2PA-marked bytes."""
    provenance = {'digitalSourceType': IPTC_GENERATED, 'generator': generator, 'model': model,
                  'created': datetime.now(timezone.utc).isoformat(), 'media_type': media_type}
    result = {'content': content, 'provenance': provenance, 'c2pa': None, 'c2pa_error': None}
    tool = shutil.which('c2patool')
    if not tool:
        result['c2pa_error'] = 'c2patool not found'
        return result
    if path is None:
        result['c2pa_error'] = 'no media path supplied'
        return result
    try:
        with tempfile.TemporaryDirectory(prefix='ai-provenance-') as temporary:
            directory = Path(temporary)
            source = Path(path)
            staged = directory / ('input' + source.suffix)
            output = directory / ('marked' + source.suffix)
            shutil.copyfile(source, staged)
            manifest = directory / 'manifest.json'
            manifest.write_text(json.dumps({'claim_generator': generator, 'assertions': [
                {'label': 'c2pa.actions', 'data': {'actions': [
                    {'action': 'c2pa.created', 'digitalSourceType': IPTC_GENERATED}]}}]}), encoding='utf-8')
            completed = subprocess.run(  # nosec B603
                [tool, str(staged), '--manifest', str(manifest), '-o', str(output)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
            if completed.returncode:
                result['c2pa_error'] = 'c2patool failed'
            elif not output.is_file() or output.is_symlink():
                result['c2pa_error'] = 'c2patool produced no regular output'
            else:
                result['c2pa'] = output.read_bytes()
    except subprocess.TimeoutExpired:
        result['c2pa_error'] = 'c2patool timeout'
    except OSError:
        result['c2pa_error'] = 'c2patool could not mark the media'
    return result


def label_published_content(text: str, *, label: str = 'Generated with AI') -> str:
    prefix = label + '\n'
    return text if text.startswith(prefix) else prefix + text
