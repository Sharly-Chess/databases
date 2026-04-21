import argparse
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from sqlite3 import Connection, connect
from urllib.parse import urlsplit

import requests

from aes_ecb import AesEcb
from progress import Progress


class SqliteGenerator(ABC):
    """An abstract SQLite generator class."""

    def __init__(self):
        self.output_file: Path = Path(self.default_output_filename)
        self.key: str = ''

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    @property
    @abstractmethod
    def version(self) -> int:
        # Increment when the schema changes so consumers can detect the format version.
        pass

    @property
    @abstractmethod
    def default_output_filename(self) -> str:
        pass

    def parse_arguments(
        self,
    ):
        parser = argparse.ArgumentParser(description=self.description)
        parser.add_argument(
            '--output',
            type=Path,
            required=False,
            help='Path for the output SQLite encrypted file',
        )
        parser.add_argument(
            '-k',
            '--key',
            type=str,
            required=True,
            help='Key used for AES-CBC encryption',
        )
        args = parser.parse_args()
        if args.output:
            self.output_file: Path = args.output.resolve()
        self.key: str = args.key

    @staticmethod
    def _download_file(
        url: str,
        target_dir: Path,
        target_filename: str | None = None,
    ) -> Path:
        response = requests.get(url, allow_redirects=True, timeout=60)
        if response.status_code != 200:
            raise RuntimeError(f'Download failed with HTTP code {response.status_code}')

        content_length: int = int(response.headers.get('content-length', 0))
        if content_length > 100 * 1_024:
            print(f'Received {content_length / 1_048_576:.1f} MB.')
        elif content_length:
            print(f'Received {content_length / 1_024:.1f} KB.')
        else:
            print('Downloaded complete.')

        print('Reading data...')
        if not target_filename:
            target_filename = urlsplit(url).path.split('/')[-1]
        target_file = target_dir / target_filename
        read: int = 0
        with open(target_file, 'wb') as f:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                f.write(chunk)
                read += len(chunk)
        if content_length:
            print('Done.')
        elif read > 100 * 1_024:
            print(f'Read {read / 1_048_576:.1f} MB.')
        else:
            print(f'Read {read / 1_024:.1f} KB.')
        if not target_file.exists():
            raise RuntimeError('No data read.')
        return target_file

    @classmethod
    def _create_sqlite_database(
        cls,
        sqlite_file: Path,
    ) -> Connection:
        sqlite_file.unlink(missing_ok=True)
        sqlite_file.parent.mkdir(parents=True, exist_ok=True)
        return connect(database=sqlite_file, detect_types=1, uri=True)

    def run(self):
        self.parse_arguments()
        with tempfile.TemporaryDirectory() as tmp:
            sqlite_file: Path = self.generate_sqlite_database(Path(tmp))
            AesEcb.encrypt_file(sqlite_file, self.output_file, self.key)
        print(f'SQLite database encrypted to {self.output_file}.')

    @abstractmethod
    def generate_sqlite_database(
        self,
        tmp_dir: Path,
    ) -> Path:
        pass
