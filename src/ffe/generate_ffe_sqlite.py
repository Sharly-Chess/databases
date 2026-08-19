#!/usr/bin/env python3
"""
Standalone script: download the FFE player database (Data.mdb), convert it to SQLite,
and enrich it with arbiter titles scraped from the FFE website.
Does not depend on the full Sharly Chess app environment — only requires `requests`.
"""

import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from html.parser import HTMLParser
from pathlib import Path
from sqlite3 import Connection, Cursor

import requests

from downloader import ProxyMode

sys.path.extend(
    map(
        str,
        [
            Path(__file__).parents[1],  # The path to the sources of the application
        ],
    )
)

from progress import Progress
from sqlite_generator import SqliteGenerator


class FFEPageParser(HTMLParser):
    """Minimal HTML parser that extracts ASP.NET viewstate fields, table rows,
    and whether a 'next page' arrow is present."""

    def __init__(self):
        super().__init__()
        self.viewstate: str = ''
        self.viewstate_generator: str = ''
        self.rows: list[list[str]] = []
        self.has_next_page: bool = False
        self._in_tr = False
        self._current_row: list[str] = []
        self._in_td = False
        self._current_td = ''

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'tr':
            self._in_tr = True
            self._current_row = []
        elif tag == 'td' and self._in_tr:
            self._in_td = True
            self._current_td = ''
        elif tag == 'input':
            id_ = attrs_dict.get('id', '')
            if id_ == '__VIEWSTATE':
                self.viewstate = attrs_dict.get('value', '') or ''
            elif id_ == '__VIEWSTATEGENERATOR':
                self.viewstate_generator = attrs_dict.get('value', '') or ''
        elif tag == 'img':
            src = attrs_dict.get('src', '').lower()
            if src == 'images/t_fleche_d.gif':
                self.has_next_page = True

    def handle_endtag(self, tag):
        if tag == 'tr':
            if self._in_tr:
                self.rows.append(self._current_row[:])
            self._in_tr = False
            self._current_row = []
        elif tag == 'td' and self._in_td:
            self._current_row.append(self._current_td.strip())
            self._in_td = False

    def handle_data(self, data):
        if self._in_td:
            self._current_td += data


class FfeSqliteGenerator(SqliteGenerator):

    def __init__(self):
        super().__init__()
        self.papi_converter_version: str = '1.4.0'
        self.ffe_database_url: str = 'https://www.echecs.asso.fr/Papi/PapiData.zip'
        self.ffe_public_url: str = 'http://echecs.asso.fr'
        self.mdb_filename: str = 'Data.mdb'
        self.download_max_attempts = 3
        self.ffe_leagues: list[str] = [
            'ARA',
            'BFC',
            'BRE',
            'CRS',
            'CVL',
            'EST',
            'GUA',
            'GUY',
            'HDF',
            'IDF',
            'MAR',
            'NAQ',
            'NCA',
            'NOR',
            'OCC',
            'PAC',
            'PDL',
            'POL',
            'REU',
        ]
        self.arbiter_title_from_html = {
            'Arbitre Jeune': 'AFJ',
            'Arbitre Club': 'AFC',
            'Arbitre Open 1': 'AFO1',
            'Arbitre Open 2': 'AFO2',
            'Arbitre Elite 1': 'AFE1',
            'Arbitre Elite 2': 'AFE2',
        }

    @property
    def description(self) -> str:
        return 'Generate FFE Player database'

    @property
    def version(self) -> int:
        return 1

    @property
    def default_output_filename(self) -> str:
        return f'ffe_players_v{self.version}.enc'

    @property
    def db_file(self) -> Path:
        return self.output_file.with_suffix('.db')

    @property
    def marker_prefix(self):
        return 'ffe'

    def generate_sqlite_database(
        self,
        tmp_dir: Path,
    ) -> Path:
        mdb_path: Path = self.download_ffe_mdb(tmp_dir)
        papi_converter: Path = self.download_papi_converter(tmp_dir)
        return self.convert_mdb_to_sqlite(papi_converter, mdb_path)

    @staticmethod
    def get_papi_converter_info() -> tuple[str, str, str]:
        """Returns (archive_filename, executable_subdir, executable_filename)."""
        machine = os.environ.get('BUILD_ARCH', platform.machine()).lower()
        match sys.platform:
            case 'linux':
                if machine in ('aarch64', 'arm64'):
                    return (
                        'papi-converter-linux-arm64.tar.gz',
                        'papi-converter-linux-arm64',
                        'papi-converter',
                    )
                elif machine in ('x86_64', 'amd64'):
                    return (
                        'papi-converter-linux-x86_64.tar.gz',
                        'papi-converter-linux-x86_64',
                        'papi-converter',
                    )
                else:
                    raise OSError(f'Unsupported Linux architecture: {machine}')
            case 'darwin':
                return 'papi-converter-mac.tar.gz', 'papi-converter-mac', 'papi-converter'
            case 'win32':
                return (
                    'papi-converter-windows.zip',
                    'papi-converter-windows',
                    'papi-converter.bat',
                )
            case _:
                raise NotImplementedError(f'Unsupported platform: {sys.platform}')

    def download_papi_converter(
        self,
        install_dir: Path,
    ) -> Path:
        archive_filename, executable_subdir, executable_filename = self.get_papi_converter_info()
        executable_path = install_dir / executable_subdir / executable_filename
        if executable_path.exists():
            return executable_path

        url = (
            f'https://github.com/Sharly-Chess/papi-converter/releases/download'
            f'/v{self.papi_converter_version}/{archive_filename}'
        )
        print(f'Downloading papi-converter from [{url}]...')
        archive_path: Path = self._download_file(url, install_dir)

        if archive_filename.endswith('.tar.gz'):
            with tarfile.open(archive_path, 'r:gz') as tar:
                tar.extractall(install_dir)
        else:
            with zipfile.ZipFile(archive_path, 'r') as zf:
                zf.extractall(install_dir)

        archive_path.unlink(missing_ok=True)

        if sys.platform in ('linux', 'darwin'):
            current = executable_path.stat().st_mode
            executable_path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        return executable_path

    def download_ffe_mdb(
        self,
        target_dir: Path,
    ) -> Path:
        last_publish: int | None = self._get_github_release_date('ffe-latest')
        print(f'Downloading FFE database from [{self.ffe_database_url}]...')
        zip_path: Path = self._download_file(
            self.ffe_database_url,
            target_dir,
            if_modified_since=last_publish,
            max_attempts=self.download_max_attempts,
            proxy_mode=ProxyMode.NEVER,
        )

        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(target_dir)
        zip_path.unlink()

        mdb_path = target_dir / self.mdb_filename
        if not mdb_path.exists():
            raise RuntimeError(f'[{self.mdb_filename}] not found after extraction')
        return mdb_path

    def convert_mdb_to_sqlite(
        self,
        papi_converter: Path,
        mdb_path: Path,
    ) -> Path:
        sqlite_file: Path = mdb_path.with_suffix('.db')
        sql_path = mdb_path.with_suffix('.sql')

        print('Converting MDB to SQL dump via papi-converter...')
        result = subprocess.run(
            [
                str(papi_converter),
                '--playerdb',
                str(mdb_path.resolve()),
                str(sql_path.resolve()),
            ],
            capture_output=True,
            encoding='utf-8',
        )
        if result.returncode != 0 or not sql_path.exists():
            raise RuntimeError(
                f'papi-converter failed (exit {result.returncode}):\n'
                f'stdout: {result.stdout}\nstderr: {result.stderr}'
            )

        print('Importing SQL dump into SQLite...')
        database: Connection = self._create_sqlite_database(sqlite_file)
        cursor: Cursor = database.cursor()
        cursor.executescript(sql_path.read_text(encoding='utf-8'))
        cursor.close()
        database.commit()
        sql_path.unlink(missing_ok=True)

        if not sqlite_file.exists():
            raise RuntimeError('SQLite database was not created')

        arbiters = self.scrape_ffe_arbiters()
        self.enrich_with_arbiter_titles(database, arbiters)
        database.close()

        size_mb = sqlite_file.stat().st_size / 1_048_576
        print(f'MDB → SQLite done ({size_mb:.1f} MB)')

        # Save the SQLite file to unzip it later
        # TODO remove this when not used in future releases
        shutil.copy(sqlite_file, self.db_file)

        return sqlite_file

    @staticmethod
    def _validate_ffe_licence(s: str) -> bool:
        return bool(re.match(r'^[A-Z]\d{5}$', s))

    def scrape_ffe_arbiters(self) -> dict[str, str]:
        """Returns {ffe_licence_number: arbiter_title_string} for all leagues."""
        print('Scraping FFE arbiter titles...')
        session = requests.Session()

        # Initialise — gets initial viewstate cookies
        html = session.get(self.ffe_public_url, timeout=30).text
        p = FFEPageParser()
        p.feed(html)
        viewstate = p.viewstate
        viewstate_generator = p.viewstate_generator

        arbiters: dict[str, str] = {}

        progress: Progress = Progress(len(self.ffe_leagues), delay=1)
        for index, league in enumerate(self.ffe_leagues, start=1):
            url = f'{self.ffe_public_url}/ListeArbitres.aspx?Action=DNALIGUE&Ligue={league}'
            page = 1
            while True:
                if page == 1:
                    response = session.get(url, timeout=30)
                else:
                    response = session.post(
                        url,
                        data={
                            '__EVENTTARGET': 'ctl00$ContentPlaceHolderMain$PagerFooter',
                            '__EVENTARGUMENT': 'd',
                            '__VIEWSTATE': viewstate,
                            '__VIEWSTATEGENERATOR': viewstate_generator,
                        },
                        timeout=30,
                    )

                p = FFEPageParser()
                p.feed(response.text)

                if p.viewstate:
                    viewstate = p.viewstate
                if p.viewstate_generator:
                    viewstate_generator = p.viewstate_generator

                for row in p.rows:
                    if len(row) >= 3 and self._validate_ffe_licence(row[0]):
                        title = self.arbiter_title_from_html.get(row[2], '')
                        if title:
                            arbiters[row[0]] = title

                if not p.has_next_page:
                    break
                page += 1
            progress.log(index)

        print(f'Scraped {len(arbiters)} arbiters in total.')
        return arbiters

    @staticmethod
    def enrich_with_arbiter_titles(
        database: Connection,
        arbiters: dict[str, str],
    ):
        print('Writing arbiter titles into SQLite...')
        database.execute('ALTER TABLE player ADD COLUMN ffe_arbiter_title TEXT')
        database.executemany(
            'UPDATE player SET ffe_arbiter_title = ? WHERE ffe_licence_number = ?',
            [(title, licence) for licence, title in arbiters.items()],
        )
        database.commit()
        print('Done.')


if __name__ == '__main__':
    FfeSqliteGenerator().run()
