#!/usr/bin/env python3
"""
Standalone script: generate a CSV file with the pre-registrations for France 2026.
Does not depend on the full Sharly Chess app environment — only requires `pyodbc`.
"""

import calendar
import locale
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from time import time
from typing import Any, Self
from urllib.parse import urlsplit

import pyodbc
import requests
from pyodbc import Cursor

import csv

DOWNLOAD_DIR: Path = Path(__file__).parent / 'download'
CSV_DIR: Path = Path(__file__).parent / 'output'

def download_file(
    url: str,
    filename: str | None = None,
) -> Path | None:
    """Downloads a file from a URL, return the file or None on failure."""
    DOWNLOAD_DIR.mkdir(exist_ok=True, parents=True)
    if filename is None:
        filename = urlsplit(url).path.split('/')[-1]
    file: Path = DOWNLOAD_DIR / filename
    print(f'Downloading [{url}]...')
    r = requests.get(url, stream=True)
    if not r.ok:
        print(f'Failed with HTTP code {r.status_code}.')
        return None
    print(f'Saving to [{file.name}]...')
    with open(file, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024 * 8):
            if chunk:
                f.write(chunk)
                f.flush()
                os.fsync(f.fileno())
    return file


@dataclass
class AccessDatabase:
    """Base class for Access-based databases."""
    file: Path
    _database: pyodbc.Connection | None = field(init=False, default=None)
    _cursor: pyodbc.Cursor | None = field(init=False, default=None)

    def __enter__(self) -> Self:
        db_url: str = f'DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={self.file.resolve()};'
        self._database = pyodbc.connect(db_url, readonly=True)
        self._cursor = self._database.cursor()
        return self

    def __exit__(self, exc_type, exc_value, tb):
        if self._database is not None:
            if self._cursor is not None:
                self._cursor.close()
                del self._cursor
                self._cursor = None
            self._database.close()
            del self._database
            self._database = None

    @property
    def database(self) -> pyodbc.Connection:
        assert self._database is not None
        return self._database

    @property
    def cursor(self) -> Cursor:
        assert self._cursor is not None
        return self._cursor

    def _execute(self, query: str, params: tuple = ()):
        self.cursor.execute(query, params)

    def _fetchall(self) -> list[dict[str, Any]]:
        columns = [column[0] for column in self.cursor.description]
        results = []
        for row in self.cursor.fetchall():
            results.append(dict(zip(columns, row)))
        return results

    def _fetchone(self) -> dict[str, Any] | None:
        columns = [column[0] for column in self.cursor.description]
        if row := self.cursor.fetchone():
            return dict(zip(columns, row))
        else:
            return None


class PlayerRowCleaner:
    """A utility class to transform the player data retrieved from FFA databases."""
    @staticmethod
    def clean(player: dict[str, Any]) -> dict[str, Any]:
        player['title'] = {
            '': '',
            'c': 'CM',
            'cf': 'WCM',
            'ff': 'WFM',
            'f': 'FM',
            'mf': 'WIM',
            'm': 'IM',
            'gf': 'WGM',
            'g': 'GM',
        }[player['title'].strip()]
        player['year_of_birth'] = player['year_of_birth'].year
        player['fide_id'] = int(player['fide_id']) if player['fide_id'] else None
        player['gender'] = {
            '': '',
            'F': 'W',
            'M': 'M',
        }[player['gender']]
        player['ffe_category'] = {
            '': '',
            'Ppo': 'U8',
            'Pou': 'U10',
            'Pup': 'U12',
            'Ben': 'U14',
            'Min': 'U16',
            'Cad': 'U18',
            'Jun': 'U20',
            'Sen': '20+',
            'Sep': '50+',
            'Vet': '65+',
        }[player['ffe_category'][:3]]
        if player['ffe_licence_type'] == 'N':
            player['club'] = ''
            player['ffe_league'] = ''
        return player


class FFEAccessDatabase(AccessDatabase):
    """Utility class for FFE databases (Data.mdb)."""
    def __init__(
        self,
        period: datetime | None = None,
    ):
        super().__init__(DOWNLOAD_DIR / 'Data.mdb' if period is None else Path(__file__).parent / 'archives' / f'Data-{period.year}{period.month:02d}.mdb')

    def get_players(
        self,
        elo_min: int = 0,
        elo_max: int = 0,
        women_only: bool = False,
        ffe_ids: list[int] = None,
    ) -> dict[int, dict[str, Any]]:
        query: str = f"""
SELECT 
    JOUEUR.FideTitre AS title,
    JOUEUR.Prenom AS first_name,
    JOUEUR.Nom AS last_name,
    JOUEUR.NeLe AS year_of_birth,
    JOUEUR.FideCode AS fide_id,
    JOUEUR.nrFFE AS national_licence_number,
    CLUB.Nom AS club,
    JOUEUR.Elo AS rating,
    JOUEUR.Fide AS rating_type,
    JOUEUR.Federation AS federation,
    JOUEUR.AffType AS ffe_licence_type,
    CLUB.Ligue AS ffe_league,
    JOUEUR.Ref AS ffe_id,
    JOUEUR.Sexe AS gender,
    JOUEUR.Cat AS ffe_category
FROM 
    CLUB, JOUEUR
WHERE 
    CLUB.Ref = JOUEUR.ClubRef 
    AND (JOUEUR.affType IN ('A') OR JOUEUR.Federation <> 'FRA')
    {f'AND JOUEUR.Elo >= {elo_min}' if elo_min else ''}
    {f'AND JOUEUR.Elo <= {elo_max}' if elo_max else ''}
    {f'AND JOUEUR.Sexe = \'F\'' if women_only else ''}
    {f'AND JOUEUR.Ref IN ({', '.join(str(ffe_id) for ffe_id in ffe_ids)})' if ffe_ids else ''}
"""
        with self:
            self._execute(query)
            women: dict[int, dict[str, Any]] = {
                row['ffe_id']: PlayerRowCleaner.clean(row)
                for row in self._fetchall()
            }
        return women

    def get_player(
        self,
        ffe_id: int,
        check_licence_type: bool = True
    ) -> dict[str, Any] | None:
        query: str = f"""
SELECT 
    JOUEUR.FideTitre AS title,
    JOUEUR.Prenom AS first_name,
    JOUEUR.Nom AS last_name,
    JOUEUR.NeLe AS year_of_birth,
    JOUEUR.FideCode AS fide_id,
    JOUEUR.nrFFE AS national_licence_number,
    CLUB.Nom AS club,
    JOUEUR.Elo AS rating,
    JOUEUR.Fide AS rating_type,
    JOUEUR.Federation AS federation,
    JOUEUR.AffType AS ffe_licence_type,
    CLUB.Ligue AS ffe_league,
    JOUEUR.Ref AS ffe_id,
    JOUEUR.Sexe AS gender,
    JOUEUR.Cat AS ffe_category
FROM 
    CLUB, JOUEUR
WHERE 
    CLUB.Ref = JOUEUR.ClubRef
    AND JOUEUR.Ref = {ffe_id}
    {'AND (JOUEUR.affType IN (\'A\') OR JOUEUR.Federation <> \'FRA\')' if check_licence_type else ''}
"""
        with self:
            self._execute(query)
            row: dict[str, Any] | None = self._fetchone()
        if row is None:
            return None
        return PlayerRowCleaner.clean(row)


class UpToDateFFEAccessDatabase(FFEAccessDatabase):
    def update_database_if_needed(self):
        download: bool = False
        if not self.file.exists():
            print('FFE database not found.')
            download = True
        elif time() - self.file.lstat().st_mtime > 24 * 60 * 60:
            print('FFE database obsolete.')
            self.file.unlink()
            download = True
        if download:
            ffe_database_url: str = 'https://www.echecs.asso.fr/Papi/PapiData.zip'
            zip_path = download_file(ffe_database_url)
            if not zip_path:
                sys.exit(1)
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(zip_path.parent)
            zip_path.unlink()
            mdb_path = zip_path.parent / 'Data.mdb'
            if not mdb_path.exists():
                print(f'{mdb_path.name} not found after extraction.')
                sys.exit(1)


@dataclass
class Over2200Now:
    def __init__(
        self,
    ):
        self.players_by_ffe_id: dict[int, dict[str, Any]] = {}
        last_ffe_database: UpToDateFFEAccessDatabase = UpToDateFFEAccessDatabase()
        print(f'Retrieving players over 2200 actually...')
        last_ffe_database.update_database_if_needed()
        for ffe_id, player in last_ffe_database.get_players(elo_min=2200).items():
            if ffe_id not in self.players_by_ffe_id:
                self.players_by_ffe_id[ffe_id] = player
        print(f'{len(self.players_by_ffe_id)} found, these players will be excluded from pre-registration (satisfying Elo >= 2200).')


@dataclass
class PreRegistration:
    over_2200_now: Over2200Now
    players_by_ffe_ids: dict[int, dict[str, Any]] = field(init=False, default_factory=dict)

    def add_player(
        self,
        player: dict[str, Any],
    ) -> bool:
        ffe_id: int = player['ffe_id']
        player_string: str = f'{player['comment']}: [{player['last_name']} {player['first_name']} {player['rating']}{player['rating_type']} {player['ffe_category']}{player['gender']}]'
        if ffe_id in self.players_by_ffe_ids:
            # print(f'{player_string} already pre-registered ({self.players_by_ffe_ids[ffe_id]['comment']}), skipping.')
            return False
        if ffe_id in self.over_2200_now.players_by_ffe_id:
            # print(f'{player_string} now rated [{self.over_2200_now.players_by_ffe_id[ffe_id]['rating']}], skipping.')
            return False
        self.players_by_ffe_ids[ffe_id] = player
        print(player_string)
        return True

    def export(
        self,
        base_name: str,
    ):
        CSV_DIR.mkdir(exist_ok=True, parents=True)
        csv_file: Path = CSV_DIR / f'{base_name}.csv'
        ffe_database: UpToDateFFEAccessDatabase = UpToDateFFEAccessDatabase()
        print(f'Updating {len(self.players_by_ffe_ids)} players...')
        up_to_date_players: dict[int, dict[str, Any]] = ffe_database.get_players(ffe_ids=list(self.players_by_ffe_ids.keys()))
        print(f'Checking FFE licences...')
        players: list[dict[str, Any]] = []
        for player in self.players_by_ffe_ids.values():
            if up_to_date_player := up_to_date_players.get(player['ffe_id'], None):
                up_to_date_player['comment'] = player['comment']
                up_to_date_player['status'] = 'pre_registered'
                players.append(up_to_date_player)
            elif up_to_date_player := ffe_database.get_player(player['ffe_id'], check_licence_type=False):
                print(f'{player['comment']}: [{up_to_date_player['last_name']} {up_to_date_player['first_name']} {up_to_date_player['rating']}{up_to_date_player['rating_type']} {up_to_date_player['ffe_category']}{up_to_date_player['gender']}] not pre-registered (licence type: {up_to_date_player['ffe_licence_type']}).')
            else:
                print(f'{player['comment']}: [{player['last_name']} {player['first_name']} {player['rating']}{player['rating_type']} {player['ffe_category']}{player['gender']}] not found in the database.')
        with open(csv_file, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=list(players[0].keys()))
            writer.writeheader()
            writer.writerows(players)
        print(f'{len(players)} written to [{csv_file.name}], {len(self.players_by_ffe_ids) - len(players)} skipped.')


@dataclass
class Over2200Before:
    def __init__(
        self,
        periods: list[datetime],
    ):
        self.periods: list[datetime] = periods

    def pre_registrate_players(
        self,
        pre_registration: PreRegistration,
    ):
        count: int = 0
        for period in self.periods:
            ffe_database: FFEAccessDatabase = FFEAccessDatabase(period)
            if not ffe_database.file.exists():
                print(f'No data for {calendar.month_name[period.month]} {period.year} (file {ffe_database.file.name} not found).')
                continue
            print(f'Retrieving players over 2200 for {calendar.month_name[period.month]} {period.year}...')
            players: dict[int, dict[str, Any]] = ffe_database.get_players(elo_min=2200)
            for ffe_id, player in players.items():
                player['comment'] = f'Classé{'e' if player['gender'] == 'W' else ''} {player['rating']} en {calendar.month_name[period.month]} {period.year}'
                if pre_registration.add_player(player):
                    count += 1
            print(f'{count} added, {len(players) - count} skipped.')


class Women19502199BeforeOrNow:
    def __init__(
        self,
        periods: list[datetime],
    ):
        self.periods: list[datetime] = periods

    def pre_registrate_players(
        self,
        pre_registration: PreRegistration,
    ):
        elo_min: int = 1950
        elo_max: int = 2199
        for period in self.periods:
            ffe_database: FFEAccessDatabase = FFEAccessDatabase(period)
            if not ffe_database.file.exists():
                print(f'No data for {calendar.month_name[period.month]} {period.year} (file {ffe_database.file.name} not found).')
                continue
            print(f'Retrieving women between {elo_min} and {elo_max} for {period.year}-{period.month}...')
            count: int = 0
            women = ffe_database.get_players(elo_min=elo_min, elo_max=elo_max, women_only=True)
            for ffe_id, woman in women.items():
                woman['comment'] = f'Classée {woman['rating']} en {calendar.month_name[period.month]} {period.year}'
                if pre_registration.add_player(woman):
                    count += 1
            print(f'{count} added, {len(women) - count} skipped.')
        last_ffe_database: UpToDateFFEAccessDatabase = UpToDateFFEAccessDatabase()
        last_ffe_database.update_database_if_needed()
        print(f'Retrieving women between {elo_min} and {elo_max} actually...')
        count: int = 0
        women = last_ffe_database.get_players(elo_min=elo_min, elo_max=elo_max, women_only=True)
        for ffe_id, woman in women.items():
            woman['comment'] = f'Joueuse classée {woman['rating']} en {calendar.month_name[datetime.now().month]} {datetime.now().year}'
            if pre_registration.add_player(woman):
                count += 1
        print(f'{count} added, {len(women) - count} skipped.')


class FFERankingPageParser(HTMLParser):
    def __init__(
        self,
        file: Path,
    ):
        super().__init__()
        self.rows: list[list[str]] = []
        self._in_tr = False
        self._current_row: list[str] = []
        self._in_td = False
        self._current_td = ''
        with open(file, 'r') as f:
            self.feed(f.read())
        self.ranked_player_names: list[str] = []
        for row in self.rows:
            if re.match(r'^\d+$', row[0]):
                self.ranked_player_names.append(row[2])

    def handle_starttag(self, tag, attrs):
        if tag == 'tr':
            self._in_tr = True
            self._current_row = []
        elif tag == 'td' and self._in_tr:
            self._in_td = True
            self._current_td = ''

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


class Tournament(AccessDatabase):
    def __init__(
        self,
        ffe_id: int,
        name: str,
        percent: int = 0,
        places: int = 0,
    ):
        self.ffe_id: int = ffe_id
        super().__init__(DOWNLOAD_DIR / f'{self.ffe_id}.papi')
        self.name: str = name
        self.percent: int = percent
        self.places: int = places
        assert self.places or self.percent

    def pre_registrate_players(
        self,
        pre_registration: PreRegistration,
    ):
        if not self.file.exists():
            if not download_file(f'https://www.echecs.asso.fr/Tournois/Id/{self.ffe_id}/{self.ffe_id}.papi'):
                return
        query: str = f"""
SELECT 
    JOUEUR.FideTitre AS title,
    JOUEUR.Prenom AS first_name,
    JOUEUR.Nom AS last_name,
    JOUEUR.NeLe AS year_of_birth,
    JOUEUR.FideCode AS fide_id,
    JOUEUR.nrFFE AS national_licence_number,
    JOUEUR.Club AS club,
    JOUEUR.Elo AS rating,
    JOUEUR.Fide AS rating_type,
    JOUEUR.Federation AS federation,
    JOUEUR.AffType AS ffe_licence_type,
    JOUEUR.Ligue AS ffe_league,
    JOUEUR.RefFFE AS ffe_id,
    JOUEUR.Sexe AS gender,
    JOUEUR.Cat AS ffe_category
FROM 
    JOUEUR
WHERE 
    JOUEUR.Ref <> 1
"""
        with self:
            self._execute(query)
            players_by_name: dict[str, dict[str, Any]] = {
                f'{row['last_name']} {row['first_name']}' if row['first_name'] else row['last_name']: PlayerRowCleaner.clean(row)
                for row in self._fetchall()
            }

        places: int = self.places if self.places else int(self.percent / 100 * len(players_by_name))

        ranking_filename: str = f'{self.ffe_id}_Cl.html'
        ranking_file: Path = DOWNLOAD_DIR / ranking_filename
        if not ranking_file.exists():
            if not download_file(f'https://www.echecs.asso.fr/Resultats.aspx?URL=Tournois/Id/{self.ffe_id}/{self.ffe_id}&Action=Cl', ranking_filename):
                return

        print(f'Retrieving players for tournament [{self.ffe_id} {self.name}]...')
        ranked_player_names: list[str] = FFERankingPageParser(ranking_file).ranked_player_names
        count : int = 0
        for place, player_name in enumerate(ranked_player_names[:places], start=1):
            player: dict[str, Any] = players_by_name[player_name]
            player['comment'] = f'{self.name} {place}e place'
            if pre_registration.add_player(player):
                count += 1
        print(f'{count} added, {places - count} skipped.')


def main():
    locale.setlocale(locale.LC_ALL, 'fr_FR.UTF-8')
    periods: list[datetime] = [
        datetime(2026, 2, 1),
        datetime(2026, 3, 1),
    ]
    over_2200_now: Over2200Now = Over2200Now()
    pre_registration: PreRegistration = PreRegistration(over_2200_now)
    for tournament in (
            Tournament(67714, 'Accession 2025', percent=50),
            Tournament(67717, 'Open A 2025', places=10),
            Tournament(67718, 'Open B 2025', places=1),
            Tournament(71008, 'FJ U18M 2026', places=1),
    ):
        tournament.pre_registrate_players(pre_registration)
    Over2200Before(periods).pre_registrate_players(pre_registration)
    Women19502199BeforeOrNow(periods).pre_registrate_players(pre_registration)
    pre_registration.export(f'accession_pre_registration-{datetime.now().strftime("%Y-%m-%d")}')


if __name__ == '__main__':
    main()
