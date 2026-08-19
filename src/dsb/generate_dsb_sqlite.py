#!/usr/bin/env python3
"""
Standalone script: download the DSB player database, convert it to SQLite.
Does not depend on the full Sharly Chess app environment — only requires `requests` and `chardet`.
"""
import csv
import shutil
import sys
import zipfile
from itertools import islice
from pathlib import Path
from sqlite3 import Connection, Cursor, IntegrityError
from typing import Any

import chardet

from downloader import ProxyMode

sys.path.extend(
    map(
        str,
        [
            Path(__file__).parents[1],  # The root path
        ],
    )
)

from progress import Progress
from sqlite_generator import SqliteGenerator


class DsbSqliteGenerator(SqliteGenerator):

    def __init__(self):
        super().__init__()
        # https://rating.englishchess.org.uk/help/api
        self.dsb_database_url: str = 'https://www.schachbund.de/download-dwz-daten.html?file=files/wertungsportal/downloads/export/csv/LV-0-csv.zip'
        self.download_max_attempts = 3

    @property
    def description(self) -> str:
        return 'Generate DSB Players database'

    @property
    def version(self) -> int:
        return 1

    @property
    def default_output_filename(self) -> str:
        return f'dsb_players_v{self.version}.enc'

    @property
    def db_file(self) -> Path:
        return self.output_file.with_suffix('.db')

    @property
    def marker_prefix(self):
        return 'dsb'

    def generate_sqlite_database(
        self,
        tmp_dir: Path,
    ) -> Path:
        archive_path: Path = self.download_zip_file(tmp_dir)
        leagues_csv_file, clubs_csv_file, players_csv_file = self.extract_csv_files(archive_path)
        players_by_dsb_code: dict[str, dict[str, Any]] = self.read_csv_files(leagues_csv_file, clubs_csv_file, players_csv_file)
        return self.dump_players_to_sqlite(players_by_dsb_code, tmp_dir)

    def download_zip_file(
        self,
        target_dir: Path
    ) -> Path:
        last_publish: int | None = self._get_github_release_date('fide-latest')
        print(f'Downloading DSB database from {self.dsb_database_url}...')
        archive_path: Path = self._download_file(
            self.dsb_database_url,
            target_dir,
            if_modified_since=last_publish,
            proxy_mode=ProxyMode.NEVER,
        )
        return archive_path

    def extract_csv_files(
        self,
        archive_path: Path
    ) -> tuple[Path, Path, Path]:
        print(f'Extracting archive {archive_path}...')
        with zipfile.ZipFile(archive_path, 'r') as zf:
            zf.extractall(archive_path.parent)
        archive_path.unlink(missing_ok=True)
        associations_csv_file = archive_path.with_name('verbaende.csv')
        clubs_csv_file = archive_path.with_name('vereine.csv')
        players_csv_file = archive_path.with_name('spieler.csv')
        for file in (associations_csv_file, clubs_csv_file, players_csv_file):
            if not file.is_file():
                raise RuntimeError(f'[{file}] not found after extraction')
        return associations_csv_file, clubs_csv_file, players_csv_file

    @staticmethod
    def read_csv_file(
        csv_path: Path,
        key_mapping: dict[str, str] = {},
    ) -> list[dict[str, str]]:
        csv_data: list[dict[str, str]] = []
        with open(csv_path, 'rb') as raw_file:
            encoding = chardet.detect(raw_file.read())['encoding']
        with open(csv_path, 'r', encoding=encoding) as csvfile:
            try:
                dialect = csv.Sniffer().sniff(''.join(islice(csvfile, 2)))
            except csv.Error:
                dialect = csv.excel

            csvfile.seek(0)
            reader = csv.DictReader(csvfile, dialect=dialect)
            if reader.fieldnames:
                for row in reader:
                    csv_data.append(row)
        for entry in csv_data:
            for old_key, new_key in key_mapping.items():
                if new_key:
                    entry[new_key] = entry.pop(old_key)
                else:
                    del entry[old_key]
        return csv_data

    @classmethod
    def read_csv_files(
        cls,
        associations_csv_file: Path,
        clubs_csv_file: Path,
        players_csv_file: Path,
    ) -> dict[str, dict[str, Any]]:
        """Returns a dict of players indexed by their dsb_code."""
        print(f'Reading states data from  {associations_csv_file}...')
        states_by_id: dict[str, dict[str, str]] = {}
        for association_data in cls.read_csv_file(associations_csv_file):
            if association_data['UebergeordneterVerband'] == '000':  # the parent's ID
                state_id = association_data['Landesverband']
                states_by_id[state_id] = {
                    'id': state_id,
                    'name': association_data['Verbandname'].strip(),
                }
        print(f'Read {len(states_by_id)} states.')

        print(f'Reading clubs data from  {clubs_csv_file}...')
        clubs_by_id: dict[str, dict[str, str]] = {}
        for club_data in cls.read_csv_file(clubs_csv_file):
            club_id = club_data['ZPS-Nummer']
            clubs_by_id[club_id] = {
                'id': club_id,
                'state_id': club_data['Landesverband'],
                'name': club_data['Vereinsname'],
            }
        print(f'Read {len(clubs_by_id)} clubs.')

        print(f'Reading players data from  {players_csv_file}...')
        players_by_dsb_code: dict[str, dict[str, str]] = {}
        for player_data in cls.read_csv_file(players_csv_file):
            # Unused player_data:
            # 'Mitgliedsnummer':    membership number (not unique)
            # 'Name,Vorname':       redundant with Vorname and Nachname
            # 'Spielberechtigung':  playing eligibility (always empty)
            # 'Letzte Auswertung':  last rating update (YYYYWW, can be empty)
            # 'Index':              unknown (non unique, from 1 to 678)
            dsb_code = player_data['ID']
            dsb_status = cls.sqlite_player_status_from_csv_value(player_data['Status'])
            # Keep only active players where players are declared as A (Aktiv)
            if dsb_code in players_by_dsb_code:
                old_dsb_status = players_by_dsb_code[dsb_code]['dsb_status']
                if dsb_status == 'P':
                    if old_dsb_status == 'A':
                        continue
                elif dsb_status == '':
                    if old_dsb_status in ('A', 'P'):
                        continue
            club_id = player_data['ZPS']
            club_name = ''
            dsb_state = ''
            try:
                club_data = clubs_by_id[club_id]
                club_name = club_data['name']
                dsb_state = club_data['state_id']
            except KeyError:
                # Player has an invalid club ID [{club_id}], generally overridden by other declarations with the same DSB code.
                pass
            fide_rating = cls.sqlite_player_rating_from_csv_value(player_data['FIDE-Elozahl'])
            national_rating = cls.sqlite_player_rating_from_csv_value(player_data['DWZ'])
            players_by_dsb_code[dsb_code] = {
                'last_name': player_data['Nachname'],
                'first_name': player_data['Vorname'],
                'gender': cls.sqlite_player_gender_from_csv_value(
                    player_data['Geschlecht']
                ),
                'club': club_name,
                'fide_id': cls.sqlite_player_fide_id_from_csv_value(
                    player_data['FIDE-ID']
                ),
                'fide_title': cls.sqlite_player_title_from_csv_value(
                    player_data['FIDE-Titel']
                ),
                'federation': player_data['FIDE-Land'],
                'standard_rating': fide_rating or national_rating or 0,
                'standard_rating_type': 3
                if fide_rating
                else 2
                if national_rating
                else 1,
                'rapid_rating': 0,
                'rapid_rating_type': 1,
                'blitz_rating': 0,
                'blitz_rating_type': 1,
                'year_of_birth': cls.sqlite_player_year_of_birth_from_csv_value(
                    player_data['Geburtsjahr']
                ),
                'dsb_code': dsb_code,
                'dsb_status': dsb_status,
                'dsb_state': dsb_state,
            }
        print(f'Read {len(players_by_dsb_code)} players.')

        return players_by_dsb_code

    @staticmethod
    def sqlite_player_status_from_csv_value(value: str) -> str:
        match value:
            case 'A' | 'P' | '':
                return value
            case _:
                raise ValueError(f'Unknown status value: {value}')

    @staticmethod
    def sqlite_player_fide_id_from_csv_value(value: str) -> int:
        return int(value) if value else 0

    @staticmethod
    def sqlite_player_rating_from_csv_value(value: str) -> int:
        return int(value) if value else 0

    @staticmethod
    def sqlite_player_year_of_birth_from_csv_value(value: str) -> int:
        return int(value) if value else 0

    @staticmethod
    def sqlite_player_gender_from_csv_value(value: str) -> str:
        match value:
            case '' | 'M' | 'W':
                return value
            case _:
                raise ValueError(f'Unknown gender value: {value}')

    @staticmethod
    def sqlite_player_title_from_csv_value(value: str) -> str:
        match value:
            case '' | 'WCM' | 'CM' | 'WFM' | 'FM' | 'WIM' | 'IM' | 'WGM' | 'GM':
                return value
            case _:
                raise ValueError(f'Unknown title value: {value}')

    def dump_players_to_sqlite(
        self,
        players_by_dsb_code: dict[str, dict[str, Any]],
        tmp_dir: Path,
    ) -> Path:
        sqlite_file: Path = tmp_dir / f'dsb_players_v{self.version}.db'
        # extract the number of items to calculate the ETA
        player_total_count: int = len(players_by_dsb_code)
        print(f'Dumping {player_total_count} players to {sqlite_file}...')
        progress: Progress = Progress(total_count=player_total_count)
        database: Connection = self._create_sqlite_database(sqlite_file)
        cursor: Cursor = database.cursor()
        cursor.execute(
            """
        CREATE TABLE `player` (
            `id` INTEGER NOT NULL,
            `fide_id` INTEGER,
            `last_name` TEXT NOT NULL,
            `first_name` TEXT,
            `federation` TEXT NOT NULL,
            `gender` TEXT NOT NULL,
            `fide_title` TEXT,
            `standard_rating` INTEGER NOT NULL,
            `standard_rating_type` INTEGER NOT NULL,
            `rapid_rating` INTEGER NOT NULL,
            `rapid_rating_type` INTEGER NOT NULL,
            `blitz_rating` INTEGER NOT NULL,
            `blitz_rating_type` INTEGER NOT NULL,
            `year_of_birth` INTEGER NOT NULL,
            `club` TEXT,
            `dsb_code` TEXT NOT NULL,
            `dsb_status` TEXT, 
            `dsb_state` TEXT,
            PRIMARY KEY(`id` AUTOINCREMENT),
            UNIQUE(`dsb_code`)
        )
        """
            )
        player_count: int = 0
        fields = next(iter(players_by_dsb_code.values())).keys()
        player_query = f"""INSERT INTO `player`({', '.join([f'`{c}`' for c in fields])}) VALUES({', '.join([f':{c}' for c in fields])})"""
        for player in players_by_dsb_code.values():
            player_count += 1
            try:
                cursor.execute(player_query, player)
            except IntegrityError:
                print(player)
                sys.exit(1)
            if player_count % 1_000 == 0:
                progress.log(player_count)
                if player_count % 100_000 == 0:
                    database.commit()
        progress.log(player_count)
        database.commit()
        database.execute('CREATE INDEX IF NOT EXISTS `player_dsb_code` ON `player` (`dsb_code` COLLATE NOCASE)')
        database.execute('CREATE INDEX IF NOT EXISTS `player_first_name` ON `player` (`first_name` COLLATE NOCASE)')
        database.execute('CREATE INDEX IF NOT EXISTS `player_last_name` ON `player` (`last_name` COLLATE NOCASE)')
        database.execute('CREATE INDEX IF NOT EXISTS `player_fide_id` ON `player` (`fide_id`)')
        database.commit()

        cursor.close()
        database.close()

        print(f'{player_count} players written to the database.')

        size_mb = sqlite_file.stat().st_size / 1_048_576
        print(f'CSV → SQLite done ({size_mb:.1f} MB)')

        shutil.copy(sqlite_file, self.db_file)

        return sqlite_file


if __name__ == '__main__':
    DsbSqliteGenerator().run()
