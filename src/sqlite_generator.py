import argparse
import glob
import json
import re
import tempfile
from abc import ABC, abstractmethod
from datetime import datetime
from http import HTTPMethod
from pathlib import Path
from sqlite3 import Connection, connect
from typing import Any

from aes_ecb import AesEcb
from downloader import (
    Downloader,
    DownloadUnavailable,
    SourceDataUnchanged,
    ProxyUnavailable,
)


class SqliteGenerator(Downloader, ABC):
    """An abstract SQLite generator class."""

    def __init__(self):
        super().__init__()
        self.start_date: str = datetime.now().strftime('%Y-%m-%d-%H-%M')
        self.output_file: Path = Path(self.default_output_filename)
        self.key: str = ''
        self.force_update: bool = False

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
            '--force-update',
            action='store_true',
            help='Force the update even when data is up to date',
        )
        parser.add_argument(
            '--key',
            type=str,
            required=True,
            help='Key used for AES-CBC encryption',
        )
        args = parser.parse_args()
        self.key = args.key
        self.force_update = args.force_update

    def _get_github_release_date(
        self,
        tag: str,
    ) -> int | None:
        """Get the timestamp of a GH databases release, or None on failure or if not found."""
        if self.force_update:
            return None
        url: str = f'https://api.github.com/repos/sharly-chess/databases/releases/tags/{tag}'
        print(f'Reading date of release [{tag}] from [{url}]...')
        try:
            response, _ = self._get_url_response(
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
        update_field: str = 'updated_at'
        if not (release_date := data.get(update_field, '')):
            create_field: str = 'created_at'
            if not (release_date := data.get(create_field, '')):
                print(f'Fields [{update_field}] and [{create_field}] not found.')
                print(json.dumps(data, sort_keys=True, indent=4))
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

    @property
    @abstractmethod
    def marker_prefix(self):
        """Returns the prefix to use for marker files."""

    @staticmethod
    def _markers() -> list[Path]:
        return [
            Path(filename)
            for filename in sorted(
                filename
                for filename in glob.glob('*')
                if re.match(r'^.*_\d{4}-\d{2}-\d{2}-\d{2}-\d{2}_.+', filename) and Path(filename).is_file()
            )
        ]

    def delete_markers(self):
        for marker in self._markers():
            marker.unlink()
            print(f'Deleted previous marker file [{marker.name}].')

    def create_marker(
        self,
        suffix: str,
    ):
        filename: str = f'{self.marker_prefix}_{self.start_date}_{suffix}'
        with open(Path(filename), "w") as file:
            file.write(suffix)
        print(f'Created marker file {filename}.')

    @property
    def last_marker_filename(
        self,
    ) -> str:
        try:
            return self._markers()[-1].name
        except IndexError:
            return f'{self.marker_prefix}-{self.start_date}-no-marker'

    def run(self):
        self.delete_markers()
        self.parse_arguments()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                sqlite_file: Path = self.generate_sqlite_database(Path(tmp))
            except DownloadUnavailable as error:
                print(f'::warning::Source unavailable, skipping update this run: {error}')
                self.create_marker('download-failed')
                return
            except SourceDataUnchanged:
                self.create_marker('data-unchanged')
                print('Source data unchanged, skipping update this run.')
                return
            except ProxyUnavailable:
                self.create_marker('proxy-error')
                print('Source data unchanged, skipping update this run.')
                return
            AesEcb.encrypt_file(sqlite_file, self.output_file, self.key)
            print(f'SQLite database encrypted to {self.output_file}.')
            self.post_run(sqlite_file)
            self.create_marker('update')

    @abstractmethod
    def generate_sqlite_database(
        self,
        tmp_dir: Path,
    ) -> Path:
        """Generates the SQL database file.
        Returns the path of the generated database or None if source data were unchanged."""

    def post_run(
        self,
        sqlite_file: Path,
    ):
        """Perform post operations, such as deriving old databases from the actual SQLite file."""
        pass
