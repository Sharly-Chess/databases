#!/usr/bin/env python3
"""
Standalone script: download the FFE player database (Data.mdb), convert it to SQLite.
Does not depend on the full Sharly Chess app environment — only requires `requests`.
"""

import argparse
import tempfile
import zipfile
from pathlib import Path
from sqlite3 import connect, Connection, Cursor
from typing import Callable, Any
from urllib.parse import urlsplit
from xml.etree import ElementTree

import requests

from progress import Progress

FIDE_DATABASE_URL = 'https://ratings.fide.com/download/players_list_xml_legacy.zip'
XML_FILENAME = 'players_list_xml.xml'

# Increment when the schema changes so consumers can detect the format version.
DB_VERSION = 1
DB_FILENAME = f'fide_players_v{DB_VERSION}.db'


# ---------------------------------------------------------------------------
# XML download
# ---------------------------------------------------------------------------

def download_fide_xml(target_dir: Path) -> Path:
    print(f'Downloading FIDE database from {FIDE_DATABASE_URL}...')
    response = requests.get(FIDE_DATABASE_URL, allow_redirects=True, timeout=60)
    if response.status_code != 200:
        raise RuntimeError(f'FIDE download failed with HTTP {response.status_code}')

    zip_path = target_dir / urlsplit(FIDE_DATABASE_URL).path.split('/')[-1]
    zip_path.write_bytes(response.content)

    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(target_dir)
    zip_path.unlink()

    xml_path = target_dir / XML_FILENAME
    if not xml_path.exists():
        raise RuntimeError(f'{XML_FILENAME} not found after extraction')
    return xml_path


# ---------------------------------------------------------------------------
# SQLite generation
# ---------------------------------------------------------------------------

def sqlite_gender_from_xml_value(value: str) -> str:
    match value:
        case 'F' | 'f' | 'M' | 'm':
            return value.upper()
        case _:
            raise ValueError(f'Unknown value: {value}')

def sqlite_player_title_from_xml_value(value: str) -> str:
    match value:
        case '' | 'WCM' | 'CM' | 'WFM' | 'FM' | 'WIM' | 'IM' | 'WGM' | 'GM':
            return value.upper()
        case _:
            raise ValueError(f'Unknown value: {value}')

def sqlite_arbiter_title_from_xml_value(value: str) -> str:
    for string in value.split(','):
        match string:
            case 'NA' | 'FA' | 'IA':
                return string
    return ''

def convert_xml_to_sqlite(xml_path: Path, output_path: Path):
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
    output_path.unlink(missing_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    database: Connection = connect(database=output_path, detect_types=1, uri=True)
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
        'sex': ('gender', sqlite_gender_from_xml_value),
        'title': ('fide_title', sqlite_player_title_from_xml_value),
        'o_title': ('fide_arbiter_title', sqlite_arbiter_title_from_xml_value),
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

    size_mb = output_path.stat().st_size / 1_048_576
    print(f'XML → SQLite done ({size_mb:.1f} MB)')


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description='Generate FIDE SQLite player database')
    parser.add_argument(
        '--output',
        type=Path,
        default=Path(DB_FILENAME),
        help='Path for the output SQLite file',
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        xml_path = download_fide_xml(tmp)
        convert_xml_to_sqlite(xml_path, args.output.resolve())


if __name__ == '__main__':
    main()
