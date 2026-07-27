#!/usr/bin/env python3
"""
Standalone script: download the FFE player database (Data.mdb), convert it to SQLite.
Does not depend on the full Sharly Chess app environment — only requires `requests` and `cryptography`.
"""

import sys
import tempfile
import zipfile
from pathlib import Path
from sqlite3 import Connection, Cursor
from typing import Callable, Any
from xml.etree import ElementTree

sys.path.extend(
    map(
        str,
        [
            Path(__file__).parents[1],  # The path to the sources of the application
        ],
    )
)

from aes_ecb import AesEcb
from progress import Progress
from sqlite_generator import DownloadUnavailable, SqliteGenerator


class FideSqliteGenerator(SqliteGenerator):

    def __init__(self):
        super().__init__()
        self.fide_database_url: str = 'https://ratings.fide.com/download/players_list_xml_legacy.zip'
        self.xml_filename = 'players_list_xml.xml'

        # The FIDE server times out intermittently, so downloads are retried.
        self.download_max_attempts = 50
        self.download_retry_delay = 30

    @property
    def description(self) -> str:
        return 'Generate FIDE Players database'

    @property
    def version(self) -> int:
        return 2

    @property
    def default_output_filename(self) -> str:
        return f'fide_players_v{self.version}.enc'

    @property
    def legacy_versions(self) -> list[int]:
        # Older clients look the database up by its versioned filename, so for
        # each version listed here we publish a file with that schema, derived
        # from the current database. Add an entry (and a builder in
        # `_legacy_builders`) whenever the schema changes.
        return [1]

    def output_file_for_version(self, version: int) -> Path:
        # Sits next to the current output (default or --output), only the
        # version in the filename differs.
        return self.output_file.with_name(f'fide_players_v{version}.enc')

    @property
    def _legacy_builders(self) -> dict[int, Callable[[Path, Path], Path]]:
        return {
            1: self.build_v1_database,
        }

    def run(self):
        self.parse_arguments()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            # The XML is downloaded and parsed only once, for the current schema.
            try:
                sqlite_file: Path = self.generate_sqlite_database(tmp_dir)
            except DownloadUnavailable as error:
                print(f'::warning::Source unavailable, skipping update this run: {error}')
                return
            AesEcb.encrypt_file(sqlite_file, self.output_file, self.key)
            print(f'SQLite database encrypted to {self.output_file}.')
            # Every legacy version is derived from it with a plain SQL copy.
            for version in self.legacy_versions:
                builder = self._legacy_builders.get(version)
                if builder is None:
                    raise ValueError(f'No legacy database builder for version {version}')
                legacy_file: Path = builder(sqlite_file, tmp_dir)
                legacy_output: Path = self.output_file_for_version(version)
                AesEcb.encrypt_file(legacy_file, legacy_output, self.key)
                print(f'Legacy (v{version}) database encrypted to {legacy_output}.')

    def generate_sqlite_database(
        self,
        tmp_dir: Path,
    ) -> Path:
        xml_path: Path = self.download_xml_file(tmp_dir)
        return self.convert_xml_to_sqlite(xml_path)

    @classmethod
    def build_v1_database(
        cls,
        sqlite_file: Path,
        tmp_dir: Path,
    ) -> Path:
        """Build the v1 database (no `fide_women_title` column) from the current one.

        In the v1 schema `fide_title` held the raw FIDE `<title>` value, i.e. the
        open title when present, otherwise the women's title. That is reconstructed
        here from the two split columns, so no second download/parse is needed.
        """
        print('Deriving legacy (v1) database...')
        legacy_file: Path = tmp_dir / 'players_list_xml_v1.db'
        database: Connection = cls._create_sqlite_database(legacy_file)
        database.execute(f"ATTACH DATABASE '{sqlite_file}' AS current")
        database.execute(
            """
        CREATE TABLE `player` (
            `id` INTEGER NOT NULL,
            `fide_id` INTEGER NOT NULL,
            `last_name` TEXT NOT NULL,
            `first_name` TEXT,
            `federation` TEXT NOT NULL,
            `gender` TEXT NOT NULL,
            `fide_title` TEXT,
            `standard_rating` INTEGER NOT NULL,
            `rapid_rating` INTEGER NOT NULL,
            `blitz_rating` INTEGER NOT NULL,
            `year_of_birth` INTEGER NOT NULL,
            `k_standard` INTEGER NOT NULL,
            `k_rapid` INTEGER NOT NULL,
            `k_blitz` INTEGER NOT NULL,
            `fide_arbiter_title` TEXT NOT NULL,
            PRIMARY KEY(`id` AUTOINCREMENT),
            UNIQUE(`fide_id`)
        )
        """
        )
        database.execute(
            """
        INSERT INTO `player` (
            `id`, `fide_id`, `last_name`, `first_name`, `federation`, `gender`,
            `fide_title`, `standard_rating`, `rapid_rating`, `blitz_rating`,
            `year_of_birth`, `k_standard`, `k_rapid`, `k_blitz`, `fide_arbiter_title`
        )
        SELECT
            `id`, `fide_id`, `last_name`, `first_name`, `federation`, `gender`,
            CASE WHEN `fide_title` != '' THEN `fide_title` ELSE `fide_women_title` END,
            `standard_rating`, `rapid_rating`, `blitz_rating`,
            `year_of_birth`, `k_standard`, `k_rapid`, `k_blitz`, `fide_arbiter_title`
        FROM `current`.`player`
        """
        )
        database.execute('CREATE INDEX IF NOT EXISTS `player_first_name` ON `player` (`first_name` COLLATE NOCASE)')
        database.execute('CREATE INDEX IF NOT EXISTS `player_last_name` ON `player` (`last_name` COLLATE NOCASE)')
        database.execute('CREATE INDEX IF NOT EXISTS `player_fide_id` ON `player` (`fide_id`)')
        database.commit()
        database.close()

        size_mb = legacy_file.stat().st_size / 1_048_576
        print(f'Legacy (v1) database built ({size_mb:.1f} MB)')
        return legacy_file

    def download_xml_file(
        self,
        target_dir: Path,
    ) -> Path:
        last_publish: int | None = self._get_github_release_date('fide-latest')
        print(f'Downloading FIDE database from [{self.fide_database_url}]...')
        zip_path: Path = self._download_file(
            self.fide_database_url,
            target_dir,
            if_modified_since=last_publish,
            max_attempts=self.download_max_attempts,
            retry_delay=self.download_retry_delay,
            anonymize=True,
        )

        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(target_dir)
        zip_path.unlink()

        xml_path = target_dir / self.xml_filename
        if not xml_path.exists():
            raise RuntimeError(f'{self.xml_filename} not found after extraction')
        return xml_path

    @staticmethod
    def sqlite_gender_from_xml_value(value: str) -> str:
        match value:
            case 'F' | 'f' | 'M' | 'm':
                return value.upper()
            case _:
                raise ValueError(f'Unknown value: {value}')

    @staticmethod
    def sqlite_open_title_from_xml_value(value: str) -> str:
        # The FIDE `<title>` field holds the player's highest title, which may be
        # a women's title. Women's titles are stored separately (see w_title), so
        # here we only keep genuine open titles and drop women's ones.
        value = value.upper()
        match value:
            case '' | 'CM' | 'FM' | 'IM' | 'GM':
                return value
            case 'WCM' | 'WFM' | 'WIM' | 'WGM':
                return ''
            case _:
                raise ValueError(f'Unknown value: {value}')

    @staticmethod
    def sqlite_women_title_from_xml_value(value: str) -> str:
        value = value.upper()
        match value:
            case '' | 'WCM' | 'WFM' | 'WIM' | 'WGM':
                return value
            case _:
                raise ValueError(f'Unknown value: {value}')

    @staticmethod
    def sqlite_arbiter_title_from_xml_value(value: str) -> str:
        for string in value.split(','):
            match string:
                case 'NA' | 'FA' | 'IA':
                    return string
        return ''

    @classmethod
    def convert_xml_to_sqlite(
        cls,
        xml_path: Path,
    ) -> Path:
        sqlite_file: Path = xml_path.with_suffix('.db')
        print('Loading XML data...')
        context = ElementTree.iterparse(xml_path, events=('start', 'end'))
        # extract the number of items to calculate the ETA
        with open(xml_path, 'r') as f:
            player_total_count: int = sum(
                1 for line in f if line.startswith('<player>')
            )
        print(f'{player_total_count} players to add.')
        progress: Progress = Progress(total_count=player_total_count)
        print('Converting XML to SQLite...')
        database: Connection = cls._create_sqlite_database(sqlite_file)
        cursor: Cursor = database.cursor()
        cursor.execute(
            """
        CREATE TABLE `player` (
            `id` INTEGER NOT NULL,
            `fide_id` INTEGER NOT NULL,
            `last_name` TEXT NOT NULL,
            `first_name` TEXT,
            `federation` TEXT NOT NULL,
            `gender` TEXT NOT NULL,
            `fide_title` TEXT,
            `fide_women_title` TEXT,
            `standard_rating` INTEGER NOT NULL,
            `rapid_rating` INTEGER NOT NULL,
            `blitz_rating` INTEGER NOT NULL,
            `year_of_birth` INTEGER NOT NULL,
            `k_standard` INTEGER NOT NULL,
            `k_rapid` INTEGER NOT NULL,
            `k_blitz` INTEGER NOT NULL,
            `fide_arbiter_title` TEXT NOT NULL,
            PRIMARY KEY(`id` AUTOINCREMENT),
            UNIQUE(`fide_id`)
        )
        """
            )
        fields: dict[str, tuple[str, Callable[[Any], Any] | None]] = {
            'fideid': ('fide_id', lambda s: int(s.strip())),
            'name': ('name', None),
            'country': ('federation', lambda s: s.upper()),
            'sex': ('gender', cls.sqlite_gender_from_xml_value),
            'title': ('fide_title', cls.sqlite_open_title_from_xml_value),
            'w_title': ('fide_women_title', cls.sqlite_women_title_from_xml_value),
            'o_title': ('fide_arbiter_title', cls.sqlite_arbiter_title_from_xml_value),
            'rating': ('standard_rating', int),
            'rapid_rating': ('rapid_rating', int),
            'blitz_rating': ('blitz_rating', int),
            'birthday': ('year_of_birth', lambda s: int(s) if s else 0),
            'k': ('k_standard', lambda s: int(s) if s else None),
            'rapid_k': ('k_rapid', lambda s: int(s) if s else None),
            'blitz_k': ('k_blitz', lambda s: int(s) if s else None),
        }
        db_columns = [field[0] for field in fields.values() if field[0] != 'name']
        db_columns += [
            'first_name',
            'last_name',
        ]
        player_query = f"""INSERT INTO `player`({', '.join(db_columns)}) VALUES({', '.join([f':{c}' for c in db_columns])})"""
        player_count: int = 0
        data: dict[str, Any] = {}
        root = next(context)[1]

        for event, elem in context:
            if event == 'start' and elem.tag == 'player':
                data = {}

            if event == 'end' and elem.tag == 'player':
                player_count += 1
                cursor.execute(player_query, data)
                if player_count % 1_000 == 0:
                    progress.log(player_count)
                    if player_count % 100_000 == 0:
                        database.commit()

            elif event == 'end' and elem.tag in fields:
                (field_name, field_function) = fields[elem.tag]
                data[field_name] = elem.text or ''
                elem.clear()
                root.clear()
                if field_function:
                    data[field_name] = field_function(data[field_name])

                if field_name == 'name':
                    if ',' in data['name']:
                        last_name, first_name = data['name'].split(',', maxsplit=1)
                        data['last_name'] = last_name.strip()
                        data['first_name'] = first_name.strip()
                    else:
                        data['last_name'] = data['name'].strip()
                        data['first_name'] = None
                    del data['name']

        progress.log(player_count)
        database.commit()
        del context
        xml_path.unlink()

        database.execute('CREATE INDEX IF NOT EXISTS `player_first_name` ON `player` (`first_name` COLLATE NOCASE)')
        database.execute('CREATE INDEX IF NOT EXISTS `player_last_name` ON `player` (`last_name` COLLATE NOCASE)')
        database.execute('CREATE INDEX IF NOT EXISTS `player_fide_id` ON `player` (`fide_id`)')
        database.commit()

        cursor.close()
        database.close()

        print(f'{player_count} players written to the database.')

        size_mb = sqlite_file.stat().st_size / 1_048_576
        print(f'XML → SQLite done ({size_mb:.1f} MB)')

        return sqlite_file


if __name__ == '__main__':
    FideSqliteGenerator().run()
