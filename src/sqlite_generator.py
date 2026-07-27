import argparse
import json
import tempfile
from abc import ABC, abstractmethod
from datetime import datetime
from http import HTTPMethod
from pathlib import Path
from sqlite3 import Connection, connect
from typing import Any

from requests import Response

from aes_ecb import AesEcb
from downloader import Downloader, DownloadUnavailable, SourceDataUnchanged


class SqliteGenerator(Downloader, ABC):
    """An abstract SQLite generator class."""

    def __init__(self):
        super().__init__()
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
        """Returns the default name to use for the output file."""

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

    def _get_github_release_date(
        self,
        tag: str,
    ) -> int | None:
        """Get the timestamp of a GH databases release, or None on failure or if not found."""
        url: str = f'https://api.github.com/repos/sharly-chess/databases/releases/tags/{tag}'
        print(f'Reading date of release [{tag}] from [{url}]...')
        try:
            response: Response = self._get_url_response(
                url,
                method=HTTPMethod.GET,
            )
        except DownloadUnavailable as error:
            print(f'Could not get the timestamp for release [{tag}]: {error}.')
            return None
        content: str = response.content.decode()
        try:
            data: dict[str, Any] = json.loads(content)
        except json.JSONDecodeError as error:
            print(f'Invalid response from GitHub: {error}.')
            return None
        date_field: str = 'created_at'
        release_date: str = data.get(date_field, '')
        if not release_date:
            print(f'Field [{date_field}] not found.')
            return None
        try:
            print(f'Date of [{tag}] on GitHub is [{release_date}].')
            return int(datetime.fromisoformat(release_date).timestamp())
        except (TypeError, ValueError) as error:
            print(f'Invalid release date [{release_date}]: {error}.')
            return None

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
            try:
                sqlite_file: Path = self.generate_sqlite_database(Path(tmp))
            except DownloadUnavailable as error:
                print(f'::warning::Source unavailable, skipping update this run: {error}')
                return
            except SourceDataUnchanged:
                print('Source data unchanged, skipping update this run.')
                return
            AesEcb.encrypt_file(sqlite_file, self.output_file, self.key)
        print(f'SQLite database encrypted to {self.output_file}.')

    @abstractmethod
    def generate_sqlite_database(
        self,
        tmp_dir: Path,
    ) -> Path:
        """Generates the SQL database file.
        Returns the path of the generated database or None if source data were unchanged."""
