import argparse
import json
import os
import tempfile
import time
from abc import ABC, abstractmethod
from datetime import datetime
from http import HTTPMethod
from pathlib import Path
from sqlite3 import Connection, connect
from typing import Literal, Any
from urllib.parse import urlsplit

from httpdate import httpdate_to_unixtime, unixtime_to_httpdate

from aes_ecb import AesEcb
from requests import get, head, Response
from requests.exceptions import RequestException


class DownloadUnavailable(RuntimeError):
    """The source could not be reached (timeout/connection error) after retries.

    Raised so the workflow can treat a transient outage as "no update this run"
    rather than a hard failure — FIDE intermittently drops CI runner IPs.
    """


class SourceDataUnchanged(RuntimeError):
    """The source data has not changed."""


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

    # FIDE blocks GitHub-hosted (Azure) runner IPs at the firewall, so an
    # egress proxy can be supplied via the standard HTTPS_PROXY/HTTP_PROXY
    # env vars (honoured automatically) or DOWNLOAD_PROXY for an explicit one.
    PROXY = os.environ.get('DOWNLOAD_PROXY')
    PROXIES = {
        'http': PROXY,
        'https': PROXY,
    } if PROXY else None

    # Sent as a precaution: some servers reject the default python-requests
    # User-Agent. Not the cause of the observed connect timeouts (those happen
    # before any request is sent), just harmless defensive hygiene.
    DOWNLOAD_USER_AGENT = (
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36'
    )
    HEADERS = {
        'User-Agent': DOWNLOAD_USER_AGENT,
    }

    DEFAULT_MAX_ATTEMPTS = 1
    DEFAULT_RETRY_DELAY = 30

    @classmethod
    def _get_url_response(
        cls,
        url: str,
        method: Literal[HTTPMethod.GET, HTTPMethod.HEAD, ],
        max_attempts: int | None = None,
        retry_delay: int | None = None,
    ) -> Response:
        """Performs a GET or HEAD request to the specified URL and returns the response.
        The retry delay (in seconds) is doubled after each failed attempt."""
        if method == HTTPMethod.GET:
            print('Downloading content...')
        else:
            print('Downloading information...')
        retry_delay = retry_delay or cls.DEFAULT_RETRY_DELAY
        max_attempts = max_attempts or cls.DEFAULT_MAX_ATTEMPTS
        for attempt in range(1, max_attempts + 1):
            try:
                function = get if method == HTTPMethod.GET else head
                return function(
                    url,
                    allow_redirects=True,
                    timeout=(60, 300),
                    headers=cls.HEADERS,
                    proxies=cls.PROXIES,
                )
            except RequestException as error:
                print(f'Download attempt {attempt} failed ({error}); retrying in {retry_delay}s...')
                time.sleep(retry_delay)
                retry_delay *= 2
        raise DownloadUnavailable(f'Download failed after {max_attempts} attempts.')

    @classmethod
    def _get_github_release_date(
        cls,
        tag: str,
    ) -> int | None:
        """Get the timestamp of a GH databases release, or None on failure or if not found."""
        url: str = f'https://api.github.com/repos/sharly-chess/databases/releases/tags/{tag}'
        print(f'Reading date of release [{tag}] from [{url}]...')
        try:
            response: Response = cls._get_url_response(
                url,
                method=HTTPMethod.GET,
            )
        except DownloadUnavailable as error:
            print(f'Could not get the timestamp for release [{tag}]: {error}.')
            return None
        content: str = response.content.decode()
        date_field: str = 'created_at'
        try:
            data: dict[str, Any] = json.loads(content)
        except json.JSONDecodeError as error:
            print(f'Invalid response from GitHub: {error}.')
            return None
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
    def _download_file(
        cls,
        url: str,
        target_dir: Path,
        if_modified_since: int | None = None,
        target_filename: str | None = None,
        max_attempts: int | None = None,
        retry_delay: int | None = None,
    ) -> Path:
        """Download a file from the specified URL.
        if *if_modified_since* is not None:
        - a HEAD request is performed to get the last modification date of the ressource.
        - if the HEAD request fails (e.g. HTTP error, no last modification date, ...), a *DownloadUnavailable* exception is raised.
        - if the last modification date of the ressource is older than *if_modified_since* a *SourceDataUnchanged* exception is raised.
        - otherwise the download is performed and the path of the resulting file is returned (a *DownloadUnavailable* exception is raised on failure).
        """
        if if_modified_since:
            head_response: Response = cls._get_url_response(
                url,
                method=HTTPMethod.HEAD,
                max_attempts=max_attempts,
                retry_delay=retry_delay,
            )
            last_modified_header: str = 'Last-Modified'
            last_modified: str = head_response.headers.get(last_modified_header, '')
            if not last_modified:
                raise DownloadUnavailable(f'Header [{last_modified_header}] not found.')
            print(f'{last_modified_header}: {last_modified}')
            last_modified_timestamp: int = httpdate_to_unixtime(last_modified)
            if_modified_since_str: str = unixtime_to_httpdate(if_modified_since)
            if last_modified_timestamp < if_modified_since:
                raise SourceDataUnchanged(f'URL is unchanged since [{if_modified_since_str}].')
            print(f'URL has changed since [{if_modified_since_str}].')

        get_response: Response = cls._get_url_response(
            url,
            method=HTTPMethod.GET,
            max_attempts=max_attempts,
            retry_delay=retry_delay,
        )

        if get_response.status_code != 200:
            raise DownloadUnavailable(f'Download failed with HTTP code {get_response.status_code}')

        content_length: int = int(get_response.headers.get('content-length', 0))
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
            for chunk in get_response.iter_content(chunk_size=1024 * 1024):
                f.write(chunk)
                read += len(chunk)
        if content_length:
            print('Done.')
        elif read > 100 * 1_024:
            print(f'Read {read / 1_048_576:.1f} MB.')
        else:
            print(f'Read {read / 1_024:.1f} KB.')
        if not target_file.exists():
            raise DownloadUnavailable('No data read.')
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
