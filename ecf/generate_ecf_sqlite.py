#!/usr/bin/env python3
"""
Standalone script: download the ECF player database (Data.mdb), convert it to SQLite.
Does not depend on the full Sharly Chess app environment — only requires `requests` and `chardet`.
"""
import csv
from itertools import islice

import chardet
import sys
from pathlib import Path
from sqlite3 import Connection, Cursor, IntegrityError
from typing import Any

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


class EcfSqliteGenerator(SqliteGenerator):

    ECF_DATABASE_URL = 'https://rating.englishchess.org.uk/v2/new/api.php?v2/rating_list_csv'
    XML_FILENAME = 'players_list_xml.xml'

    @property
    def description(self) -> str:
        return 'Generate ECF Players database'

    @property
    def version(self) -> int:
        return 1

    @property
    def default_output_filename(self) -> str:
        return f'ecf_players_v{self.version}.enc'

    @classmethod
    def generate_sqlite_database(
        cls,
        tmp_dir: Path,
    ) -> Path:
        xml_path: Path = cls.download_csv_file(tmp_dir)
        return cls.convert_csv_to_sqlite(xml_path)

    @classmethod
    def download_csv_file(
        cls,
        target_dir: Path) -> Path:
        print(f'Downloading ECF database from {cls.ECF_DATABASE_URL}...')
        csv_path: Path = cls._download_file(cls.ECF_DATABASE_URL, target_dir, target_filename='ecf_players.csv', timeout=120)
        return csv_path

    @classmethod
    def read_csv_file(cls, csv_path: Path) -> list[dict[str, str]]:
        csv_players: list[dict[str, str]] = []
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
                    csv_players.append(row)
        return csv_players

    @staticmethod
    def sqlite_gender_from_csv_value(value: str) -> str:
        match value:
            case 'F' | 'M':
                return value
            case 'N' | '':
                return ''
            case _:
                raise ValueError(f'Unknown gender value: {value}')

    @staticmethod
    def sqlite_player_title_from_csv_value(value: str) -> str:
        match value:
            case '' | 'WCM' | 'CM' | 'WFM' | 'FM' | 'WIM' | 'IM' | 'WGM' | 'GM':
                return value
            case 'NM':
                return ''
            case _:
                for title in ['FM', 'IM', 'GM']:
                    if value.startswith(f'{title}/'):
                        return title
                raise ValueError(f'Unknown title value: {value}')

    @staticmethod
    def sqlite_player_club_from_csv_dict(d: dict[str, str]) -> str:
        if d['club_code'].startswith('F'):  # F + FED
            return ''
        if d['club_code'].startswith('I'):  # I + ENG/GUE/IRE/JER/NIR/SCO/WAL
            return ''
        match d['club_code']:
            case 'ONLN':  # Online events
                return ''
            case 'XXXX':  # Unknown
                return ''
        return d['club_name']

    @staticmethod
    def sqlite_player_rating_from_csv_value(value: str) -> int:
        return int(value) if value else 0

    @staticmethod
    def sqlite_player_fide_id_from_csv_value(value: str) -> int:
        return int(value) if value else 0

    @staticmethod
    def sqlite_player_member_no_from_csv_value(value: str) -> int:
        return int(value) if value else 0

    @classmethod
    def convert_csv_to_sqlite(
        cls,
        csv_path: Path,
    ) -> Path:
        sqlite_file: Path = csv_path.with_suffix('.db')
        print('Loading CSV data...')
        csv_players: list[dict[str, str]] = cls.read_csv_file(csv_path)
        # extract the number of items to calculate the ETA
        player_total_count: int = len(csv_players)
        print(f'{player_total_count} players to add.')
        progress: Progress = Progress(total_count=player_total_count)
        print('Converting CSV to SQLite...')
        database: Connection = cls._create_sqlite_database(sqlite_file)
        cursor: Cursor = database.cursor()
        cursor.execute(
            """
        CREATE TABLE `player` (
            `id` INTEGER NOT NULL,
            `ecf_member_no` INTEGER NOT NULL,
            `fide_id` INTEGER,
            `ecf_code` TEXT NOT NULL,
            `last_name` TEXT NOT NULL,
            `first_name` TEXT,
            `federation` TEXT NOT NULL,
            `gender` TEXT NOT NULL,
            `fide_title` TEXT,
            `standard_rating` INTEGER NOT NULL,
            `rapid_rating` INTEGER NOT NULL,
            `blitz_rating` INTEGER NOT NULL,
            `year_of_birth` INTEGER NOT NULL,
            `club` TEXT,
            PRIMARY KEY(`id` AUTOINCREMENT),
            UNIQUE(`ecf_code`)
        )
        """
            )
        player_count: int = 0
        fields: list[str] = [
            'ecf_member_no',
            'fide_id',
            'ecf_code',
            'federation',
            'gender',
            'fide_title',
            'standard_rating',
            'rapid_rating',
            'blitz_rating',
            'year_of_birth',
            'club',
            'last_name',
            'first_name',
        ]
        player_query = f"""INSERT INTO `player`({', '.join([f'`{c}`' for c in fields])}) VALUES({', '.join([f':{c}' for c in fields])})"""
        for csv_player in csv_players:
            player: dict[str, Any] = {
                'ecf_member_no': cls.sqlite_player_member_no_from_csv_value(csv_player['member_no']),
                'fide_id': cls.sqlite_player_fide_id_from_csv_value(csv_player['FIDE_no']),
                'ecf_code': csv_player['ECF_code'].strip(),
                'federation': csv_player['nation'],
                'gender': cls.sqlite_gender_from_csv_value(csv_player['gender']),
                'fide_title': cls.sqlite_player_title_from_csv_value(csv_player['title']),
                'standard_rating': cls.sqlite_player_rating_from_csv_value(csv_player['revised_standard']),
                'rapid_rating': cls.sqlite_player_rating_from_csv_value(csv_player['revised_rapid']),
                'blitz_rating': cls.sqlite_player_rating_from_csv_value(csv_player['revised_blitz']),
                'year_of_birth': 0,  # no year of birth in the ENG database
                'club': cls.sqlite_player_club_from_csv_dict(csv_player),
            }
            if ',' in csv_player['full_name']:
                last_name, first_name = csv_player['full_name'].split(',', maxsplit=1)
                player['last_name'] = last_name.strip()
                player['first_name'] = first_name.strip()
            else:
                player['last_name'] = csv_player['full_name'].strip()
                player['first_name'] = None
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
        csv_path.unlink()

        database.execute('CREATE INDEX IF NOT EXISTS `player_ecf_code` ON `player` (`ecf_code` COLLATE NOCASE)')
        database.execute('CREATE INDEX IF NOT EXISTS `player_first_name` ON `player` (`first_name` COLLATE NOCASE)')
        database.execute('CREATE INDEX IF NOT EXISTS `player_last_name` ON `player` (`last_name` COLLATE NOCASE)')
        database.execute('CREATE INDEX IF NOT EXISTS `player_fide_id` ON `player` (`fide_id`)')
        database.commit()

        cursor.close()
        database.close()

        print(f'{player_count} players written to the database.')

        size_mb = sqlite_file.stat().st_size / 1_048_576
        print(f'CSV → SQLite done ({size_mb:.1f} MB)')

        return sqlite_file


if __name__ == '__main__':
    EcfSqliteGenerator().run()
