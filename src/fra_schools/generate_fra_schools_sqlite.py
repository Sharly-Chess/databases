#!/usr/bin/env python3
"""
Standalone script: download the FRA schools data (JSON format), convert it to SQLite.
Does not depend on the full Sharly Chess app environment — only requires `requests`.
"""

import json
import re
import sys
from dataclasses import asdict
from pathlib import Path
from sqlite3 import Connection, Cursor
from typing import Callable, Any
from urllib.parse import urlencode

from downloader import DownloadUnavailable, ProxyMode

sys.path.extend(
    map(
        str,
        [
            Path(__file__).parents[1],  # The path to the sources of the application
        ],
    )
)

from fra_schools.legifrance import LegifranceClient, SchoolAbroad
from progress import Progress
from sqlite_generator import SqliteGenerator

# INSEE code for the schools abroad, which have no department.
ABROAD_DEPARTMENT_ID = '99'
ABROAD_DEPARTMENT_NAME = 'Étranger'

# The schools abroad are published next to the database, so that a run that
# can't reach Légifrance keeps the ones of the previous run.
ABROAD_FILENAME = 'fra_schools_abroad.json'
ABROAD_PUBLISHED_URL = (
    'https://github.com/Sharly-Chess/databases/releases/download/fra-schools-latest/'
    + ABROAD_FILENAME
)

# The Licence Ouverte 2.0 of the Légifrance data asks to credit the source.
RELEASE_NOTES_FILENAME = 'fra_schools_release_notes.md'
LEGIFRANCE_CREDIT = 'Légifrance (DILA), Licence Ouverte 2.0'


class FraSchoolsSqliteGenerator(SqliteGenerator):

    def __init__(self):
        super().__init__()
        self.download_max_attempts = 3

    @property
    def description(self) -> str:
        return 'Generate FRA Schools database'

    @property
    def version(self) -> int:
        return 1

    @property
    def default_output_filename(self) -> str:
        return f'fra_schools_v{self.version}.enc'

    @property
    def marker_prefix(self):
        return 'fra-schools'

    def generate_sqlite_database(
        self,
        tmp_dir: Path,
    ) -> Path:
        json_path: Path = self.download_json_file(tmp_dir)
        source, schools_abroad = self.download_schools_abroad(tmp_dir)
        Path(ABROAD_FILENAME).write_text(
            json.dumps(
                {
                    'source': source,
                    'credit': LEGIFRANCE_CREDIT,
                    'schools': [asdict(school) for school in schools_abroad],
                },
                ensure_ascii=False,
                indent=1,
            ),
            encoding='utf-8',
        )
        notes = 'Auto-updated daily'
        if source:
            notes += f'\n\nSchools abroad: {source}, {LEGIFRANCE_CREDIT}.'
        Path(RELEASE_NOTES_FILENAME).write_text(notes + '\n', encoding='utf-8')
        return self.convert_json_to_sqlite(json_path, schools_abroad)

    def download_schools_abroad(
        self,
        tmp_dir: Path,
    ) -> tuple[str | None, list[SchoolAbroad]]:
        """The title of the arrêté listing the schools abroad, and the schools."""
        # The FFE school championship (J03 art. 1.2.1) is open to the French
        # schools abroad, which the directory of the Éducation nationale does
        # not list.
        client = LegifranceClient.from_environment()
        if client is None:
            print('::warning::PISTE_CLIENT_ID and PISTE_CLIENT_SECRET not set.')
        else:
            print('Downloading the French schools abroad from Légifrance...')
            try:
                title, schools = client.schools_abroad()
                print(f'{len(schools)} schools abroad found in [{title}].')
                return title, schools
            except DownloadUnavailable as error:
                print(f'::warning::{error}')
        print(f'Keeping the previously published schools abroad from [{ABROAD_PUBLISHED_URL}]...')
        try:
            published_path: Path = self._download_file(
                ABROAD_PUBLISHED_URL,
                tmp_dir,
                target_filename=ABROAD_FILENAME,
                max_attempts=self.download_max_attempts,
            )
        except DownloadUnavailable:
            if client is None:
                print('::warning::No schools abroad published yet, skipping them.')
                return None, []
            raise
        published = json.loads(published_path.read_text(encoding='utf-8'))
        schools = [SchoolAbroad(**school) for school in published['schools']]
        print(f'{len(schools)} schools abroad kept from [{published["source"]}].')
        return published['source'], schools

    def download_json_file(
        self,
        source_file_dir: Path,
    ) -> Path:
        # The FFE school championship (J03 art. 1.2.1) is open to medical and
        # educational establishments (IME, ITEP…), listed as 'Médico-social',
        # and to adapted teaching, which includes the EREA.
        types: list[str] = ['Ecole', 'Collège', 'Lycée', 'Médico-social', 'EREA']
        # See https://data.education.gouv.fr/api/v2/console
        base_url: str = 'https://data.education.gouv.fr/api/v2/catalog/datasets/fr-en-annuaire-education/exports/json'
        url: str = (
            base_url
            + '?'
            + urlencode(
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

        print(f'Downloading FRA Schools from [{url}]...')
        return self._download_file(
            url,
            source_file_dir,
            target_filename='schools.json',
            max_attempts=self.download_max_attempts,
            proxy_mode=ProxyMode.NEVER,
        )

    @classmethod
    def convert_json_to_sqlite(
        cls,
        json_path: Path,
        schools_abroad: list[SchoolAbroad],
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
        progress.log(school_count)
        database.commit()

        if schools_abroad:
            database.execute(
                department_query,
                {'id': ABROAD_DEPARTMENT_ID, 'name': ABROAD_DEPARTMENT_NAME},
            )
            known_codes = {code for (code,) in database.execute('SELECT code FROM school')}
            abroad_rows = [
                {
                    'code': school.uai,
                    'name': cls.protect_string(school.name),
                    'department': ABROAD_DEPARTMENT_ID,
                    'postal_code': '',
                    'city': cls.protect_string(f'{school.city}, {school.country}'),
                    'type': school.levels,
                    'private': False,
                }
                for school in schools_abroad
                if school.uai not in known_codes
            ]
            database.executemany(school_query, abroad_rows)
            database.commit()
            school_count += len(abroad_rows)
            print(f'{len(abroad_rows)} schools abroad added.')

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
