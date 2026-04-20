#!/usr/bin/env python3
"""
Standalone script: download the FRA schools data (JSON format), convert it to SQLite.
Does not depend on the full Sharly Chess app environment — only requires `requests`.
"""

import json
import re
import sys
import urllib
from pathlib import Path
from sqlite3 import Connection, Cursor
from typing import Callable, Any
from urllib.parse import urlsplit

import requests
from requests import HTTPError

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


class FraSchoolsSqliteGenerator(SqliteGenerator):

    @property
    def description(self) -> str:
        return 'Generate FRA Schools database'

    @property
    def version(self) -> int:
        return 1

    @property
    def default_output_filename(self) -> str:
        return f'fra_schools_v{self.version}.enc'

    @classmethod
    def generate_sqlite_database(
        cls,
        tmp_dir: Path,
    ) -> Path:
        json_path: Path = cls.download_json_file(tmp_dir)
        return cls.convert_json_to_sqlite(json_path)

    @classmethod
    def download_json_file(
        cls,
        source_file_dir: Path,
    ) -> Path:
        types: list[str] = ['Ecole', 'Collège', 'Lycée']
        # See https://data.education.gouv.fr/api/v2/console
        base_url: str = 'https://data.education.gouv.fr/api/v2/catalog/datasets/fr-en-annuaire-education/exports/json'
        url: str = (
            base_url
            + '?'
            + urllib.parse.urlencode(
            {
                'select': ','.join(
                    [
                        'code_postal',
                        'code_departement',
                        'libelle_departement',
                        'nom_commune',
                        'type_etablissement',
                        'statut_public_prive',
                        'identifiant_de_l_etablissement',
                        'nom_etablissement',
                    ]
                ),
                'where': 'type_etablissement IN ("' + '" ,"'.join(types) + '")',
                'order_by': ','.join(
                    [
                        'code_postal',
                        'nom_commune',
                        'type_etablissement',
                        'statut_public_prive',
                        'identifiant_de_l_etablissement',
                    ]
                ),
                'limit': -1,
                'offset': 0,
                'timezone': 'UTC',
            }
        )
        )

        json_file: Path = source_file_dir / 'schools.json'
        print(f'Downloading data from [{url}].')
        response: requests.Response = requests.get(url)
        if not response.ok:
            raise HTTPError(f'Download failed with status code {response.status_code}: {response.text}')
        json_file.write_bytes(response.content)
        if not json_file.exists():
            raise HTTPError(f'No data received.')
        return json_file

    @classmethod
    def convert_json_to_sqlite(
        cls,
        json_path: Path,
    ) -> Path:
        sqlite_file: Path = json_path.with_suffix('.db')
        print('Loading JSON data...')
        data: list[dict[str, Any]] = []
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f'{len(data)} schools to add.')

        progress: Progress = Progress(
            total_count=len(data),
            delay=2,
        )
        print('Converting JSON to SQLite...')
        database: Connection = cls._create_sqlite_database(sqlite_file)
        cursor: Cursor = database.cursor()
        cursor.execute(
            """
    CREATE TABLE `department` (
        `id` TEXT NOT NULL,
        `name` TEXT NOT NULL,
        PRIMARY KEY(`id`)
    );
        """
        )
        cursor.execute(
            """
    CREATE TABLE `school` (
        `id` INTEGER NOT NULL,
        `code` TEXT NOT NULL,
        `name` TEXT NOT NULL,
        `postal_code` TEXT NOT NULL,
        `department` TEXT REFERENCES department(id),
        `city` TEXT NOT NULL,
        `type` TEXT NOT NULL,
        `private` INTEGER NOT NULL,
        PRIMARY KEY(`id` AUTOINCREMENT)
    );
        """
        )
        cursor.execute(
            """
    CREATE VIRTUAL TABLE school_fts USING fts5(
        search_text,
        content='school',
        content_rowid='id',
        tokenize='unicode61 remove_diacritics 1',
        prefix='2, 3',
    );
        """
        )

        fields: dict[str, tuple[str, Callable[[Any], Any] | None]] = {
            'identifiant_de_l_etablissement': ('code', None),
            'nom_etablissement': ('name', cls.normalize_name),
            'code_departement': (
                'department',
                lambda s: s[1:] if s.startswith('0') else s,
            ),
            'libelle_departement': ('department_name', None),
            'code_postal': ('postal_code', None),
            'nom_commune': ('city', cls.protect_string),
            'type_etablissement': ('type', None),
            'statut_public_prive': ('private', lambda s: s == 'Privé'),
        }
        # Prepare insert queries
        school_columns = [
            'code',
            'name',
            'department',
            'postal_code',
            'city',
            'type',
            'private',
        ]
        school_query = (
            f'INSERT INTO school({", ".join(school_columns)}) '
            f'VALUES({", ".join([f":{c}" for c in school_columns])})'
        )

        department_query = (
            'INSERT OR IGNORE INTO department(id, name) VALUES(:id, :name)'
        )

        school_count = 0
        to_write_schools: list[dict[str, Any]] = []
        to_write_departments: list[dict[str, Any]] = []

        for school in data:
            row = {}
            for src_field, (db_field, transform) in fields.items():
                value = school.get(src_field)
                if transform is not None:
                    value = transform(value)
                row[db_field] = value

            to_write_departments.append(
                {
                    'id': row['department'],
                    'name': row['department_name'],
                }
            )

            to_write_schools.append(
                {
                    'code': row['code'],
                    'name': row['name'],
                    'department': row['department'],
                    'postal_code': row['postal_code'],
                    'city': row['city'],
                    'type': row['type'],
                    'private': row['private'],
                }
            )

            school_count += 1
            if school_count % 1000 == 0:
                database.executemany(department_query, to_write_departments)
                database.executemany(school_query, to_write_schools)
                to_write_departments.clear()
                to_write_schools.clear()
                progress.log(school_count)
            if school_count % 100_000 == 0:
                database.commit()

        if to_write_departments:
            database.executemany(department_query, to_write_departments)
        if to_write_schools:
            database.executemany(school_query, to_write_schools)
        database.commit()

        database.execute(
            """
            INSERT INTO school_fts(rowid, search_text)
            SELECT s.id,
                lower(
                    s.code || ' ' ||
                    s.name || ' ' ||
                    s.city || ' ' ||
                    s.type || ' ' ||
                    s.postal_code
                )
            FROM school s;
        """
        )
        database.commit()

        cursor.close()
        database.close()

        print(f'{school_count} schools written to the database.')

        size_mb = sqlite_file.stat().st_size / 1_048_576
        print(f'JSON → SQLite done ({size_mb:.1f} MB)')

        return sqlite_file

    @classmethod
    def normalize_name(
        cls,
        name: str,
    ) -> str:
        name = cls.protect_string(name)
        name = name.lower().title()
        name = re.sub(
            r'\b(D\'|De|Du|Des|L\'|La|Le|Les|Au|Aux|Et|En|Sur)\b',
            lambda m: m.group(1).lower(),
            name,
        )
        name = re.sub(r'[\s\t\n]+', ' ', name)
        # All the SEGPA are written in full letters, breaking the layout.
        # This replaces them by the acronym, taking all the misspellings into account
        name = re.sub(
            r'\bSection\s(d[\'])?Enseigne(me)?ment(\sProfessionnel)?\s'
            r'Générale?(\set)?(\sProfess?ionn?el(le)?)?(\sAdaptée?)?\b',
            'SEGPA',
            name,
            flags=re.IGNORECASE,
        )
        return name

    @classmethod
    def protect_string(
        cls,
        string: str,
    ) -> str:
        return string.replace('`', "'")


if __name__ == '__main__':
    FraSchoolsSqliteGenerator().run()
