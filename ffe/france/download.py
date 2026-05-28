import os
from pathlib import Path
from urllib.parse import urlsplit

import requests

DOWNLOAD_DIR: Path = Path(__file__).parent / 'download'


def download_file(
    url: str,
    filename: str | None = None,
) -> Path | None:
    """Downloads a file from a URL, return the file or None on failure."""
    DOWNLOAD_DIR.mkdir(exist_ok=True, parents=True)
    if filename is None:
        filename = urlsplit(url).path.split('/')[-1]
    file: Path = DOWNLOAD_DIR / filename
    print(f'Downloading [{url}]...')
    r = requests.get(url, stream=True)
    if not r.ok:
        print(f'Failed with HTTP code {r.status_code}.')
        return None
    print(f'Saving to [{file.name}]...')
    with open(file, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024 * 8):
            if chunk:
                f.write(chunk)
                f.flush()
                os.fsync(f.fileno())
    return file
