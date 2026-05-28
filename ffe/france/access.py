import re
import sys
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from time import time
from typing import Any, Self

import pyodbc
from pyodbc import Cursor

from ffe.france.download import DOWNLOAD_DIR, download_file


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

    def get_players_by_ffe_id(
        self,
        elo_min: int = 0,
        elo_max: int = 0,
        women_only: bool = False,
        ffe_ids: list[int] = None,
        federations: list[str] = None,
        categories: list[str] = None,
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
    {f'AND JOUEUR.Federation IN ({', '.join(map(lambda federation: f'\'{federation}\'', federations))})' if federations else ''}
    {f'AND JOUEUR.Elo >= {elo_min}' if elo_min else ''}
    {f'AND JOUEUR.Elo <= {elo_max}' if elo_max else ''}
    {f'AND JOUEUR.Sexe = \'F\'' if women_only else ''}
    {f'AND JOUEUR.Federation IN ({', '.join(map(lambda category: f'\'{category}\'', categories))})' if categories else ''}
    {f'AND JOUEUR.Ref IN ({', '.join(str(ffe_id) for ffe_id in ffe_ids)})' if ffe_ids else ''}
"""
        with self:
            self._execute(query)
            women: dict[int, dict[str, Any]] = {
                row['ffe_id']: PlayerRowCleaner.clean(row)
                for row in self._fetchall()
            }
        return women

    def get_players(
        self,
        elo_min: int = 0,
        elo_max: int = 0,
        women_only: bool = False,
        ffe_ids: list[int] = None,
        federations: list[str] = None,
        categories: list[str] = None,
    ) -> list[dict[str, Any]]:
        return list(
            self.get_players_by_ffe_id(
                elo_min,
                elo_max,
                women_only,
                ffe_ids,
                federations,
                categories,
            ).values()
        )

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
    def __init__(self):
        super().__init__()
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
        self.players: list[dict[str, Any]] = []
        players_by_name: dict[str, dict[str, Any]] = {}
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

        ranking_filename: str = f'{self.ffe_id}_Cl.html'
        ranking_file: Path = DOWNLOAD_DIR / ranking_filename
        if not ranking_file.exists():
            if not download_file(f'https://www.echecs.asso.fr/Resultats.aspx?URL=Tournois/Id/{self.ffe_id}/{self.ffe_id}&Action=Cl', ranking_filename):
                return

        if not places:
            places = int((percent or 100) / 100 * len(players_by_name))

        print(f'Retrieving players for tournament [{self.ffe_id} {self.name}]...')
        ranked_player_names: list[str] = FFERankingPageParser(ranking_file).ranked_player_names
        count : int = 0
        for place, player_name in enumerate(ranked_player_names[:places], start=1):
            player: dict[str, Any] = players_by_name[player_name]
            player['comment'] = f'{self.name} {place}e place'
            self.players.append(player)
        print(f'{count} players retrieved.')


