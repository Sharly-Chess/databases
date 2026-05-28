#!/usr/bin/env python3
"""
Standalone script: generate a CSV file with the pre-registrations for France 2026.
Does not depend on the full Sharly Chess app environment — only requires `pyodbc`.
"""

import calendar
import locale
from dataclasses import dataclass
from datetime import datetime

from ffe.france.access import UpToDateFFEAccessDatabase, FFEAccessDatabase, Tournament
from ffe.france.player_container import PlayerContainer
from ffe.france.pre_registration import PreRegistration


class Over2200Now(PlayerContainer):
    def __init__(self):
        super().__init__()
        last_ffe_database: UpToDateFFEAccessDatabase = UpToDateFFEAccessDatabase()
        print(f'Retrieving players over 2200 actually...')
        self.add_players(last_ffe_database.get_players(elo_min=2200, federations=['FRA', ]))
        print(f'{len(self.players_by_ffe_id)} found, these players will be excluded from pre-registration (satisfying Elo >= 2200).')


@dataclass
class Over2200Before(PlayerContainer):
    def __init__(
        self,
        periods: list[datetime],
    ):
        super().__init__()
        self.periods: list[datetime] = periods
        for period in self.periods:
            ffe_database: FFEAccessDatabase = FFEAccessDatabase(period)
            if not ffe_database.file.exists():
                print(f'No data for {calendar.month_name[period.month]} {period.year} (file {ffe_database.file.name} not found).')
                continue
            print(f'Retrieving players over 2200 for {calendar.month_name[period.month]} {period.year}...')
            for player in ffe_database.get_players(elo_min=2200, federations=['FRA', ]):
                player['comment'] = f'Classé{'e' if player['gender'] == 'W' else ''} {player['rating']} en {calendar.month_name[period.month]} {period.year}'
                self.add_player(player)
        print(f'{len(self.players_by_ffe_id)} players over 2200 retrieved.')


class Women19502199BeforeOrNow(PlayerContainer):
    def __init__(
        self,
        periods: list[datetime],
    ):
        super().__init__()
        self.periods: list[datetime] = periods
        elo_min: int = 1950
        elo_max: int = 2199
        for period in self.periods:
            ffe_database: FFEAccessDatabase = FFEAccessDatabase(period)
            if not ffe_database.file.exists():
                print(f'No data for {calendar.month_name[period.month]} {period.year} (file {ffe_database.file.name} not found).')
                continue
            print(f'Retrieving women between {elo_min} and {elo_max} for {period.year}-{period.month}...')
            women = ffe_database.get_players_by_ffe_id(elo_min=elo_min, elo_max=elo_max, women_only=True, federations=['FRA', ])
            for ffe_id, woman in women.items():
                woman['comment'] = f'Classée {woman['rating']} en {calendar.month_name[period.month]} {period.year}'
                self.add_player(woman)
        last_ffe_database: UpToDateFFEAccessDatabase = UpToDateFFEAccessDatabase()
        print(f'Retrieving women between {elo_min} and {elo_max} actually...')
        women = last_ffe_database.get_players_by_ffe_id(elo_min=elo_min, elo_max=elo_max, women_only=True, federations=['FRA', ])
        for ffe_id, woman in women.items():
            woman['comment'] = f'Joueuse classée {woman['rating']} en {calendar.month_name[datetime.now().month]} {datetime.now().year}'
            self.add_player(woman)
        print(f'{len(self.players_by_ffe_id)} retrieved.')


def main():
    locale.setlocale(locale.LC_ALL, 'fr_FR.UTF-8')
    periods: list[datetime] = [
        datetime(2026, 5, 1),
    ]
    accession_pre_registration: PreRegistration = PreRegistration(Over2200Now())
    for tournament in (
            Tournament(67714, 'Accession 2025', percent=50),
            Tournament(67717, 'Open A 2025', places=10),
            Tournament(67718, 'Open B 2025', places=1),
            Tournament(71008, 'FJ U18M 2026', places=1),
    ):
        accession_pre_registration.add_players(tournament.players)
    accession_pre_registration.add_players(Over2200Before(periods).players)
    accession_pre_registration.add_players(Women19502199BeforeOrNow(periods).players)
    accession_pre_registration.export(f'accession')


if __name__ == '__main__':
    main()
