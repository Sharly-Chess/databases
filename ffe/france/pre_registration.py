import csv
from datetime import datetime
from pathlib import Path
from typing import Any

from ffe.france import CSV_DIR
from ffe.france.access import UpToDateFFEAccessDatabase
from ffe.france.player_container import PlayerContainer


class PreRegistration(PlayerContainer):
    def __init__(
        self,
        excluded_players_container: PlayerContainer | None = None,
    ):
        super().__init__()
        self.excluded_players_container: PlayerContainer = excluded_players_container or PlayerContainer()

    def add_player(self, player: dict[str, Any]):
        if player['ffe_id'] not in self.excluded_players_container.players_by_ffe_id:
            self.add_player(player)

    @property
    def excluded_players_by_ffe_id(self) -> dict[int, dict[str, Any]]:
        return self.excluded_players_container.players_by_ffe_id

    def add_players(
        self,
        players: list[dict[str, Any]],
    ) -> 'PreRegistration':
        count: int = 0
        for player in players:
            ffe_id: int = player['ffe_id']
            player_string: str = f'{player['comment']}: [{player['last_name']} {player['first_name']} {player['rating']}{player['rating_type']} {player['ffe_category']}{player['gender']}]'
            if ffe_id in self.players_by_ffe_id:
                continue
            if ffe_id in self.excluded_players_by_ffe_id:
                continue
            self.players_by_ffe_id[ffe_id] = player
            print(player_string)
            count += 1
        return self

    def export(
        self,
        base_name: str,
    ):
        CSV_DIR.mkdir(exist_ok=True, parents=True)
        csv_file: Path = CSV_DIR / f'{base_name}-{datetime.now().strftime("%Y-%m-%d")}.csv'
        ffe_database: UpToDateFFEAccessDatabase = UpToDateFFEAccessDatabase()
        print(f'Updating {len(self.players_by_ffe_id)} players...')
        up_to_date_players: dict[int, dict[str, Any]] = ffe_database.get_players_by_ffe_id(ffe_ids=list(self.players_by_ffe_id.keys()))
        print(f'Checking FFE licences...')
        players: list[dict[str, Any]] = []
        for player in sorted(self.players_by_ffe_id.values(), key=lambda p: (p['last_name'], p['first_name'])):
            if up_to_date_player := up_to_date_players.get(player['ffe_id'], None):
                up_to_date_player['comment'] = player['comment']
                up_to_date_player['status'] = 'pre_registered'
                players.append(up_to_date_player)
            elif up_to_date_player := ffe_database.get_player(player['ffe_id'], check_licence_type=False):
                print(f'{player['comment']}: [{up_to_date_player['last_name']} {up_to_date_player['first_name']} {up_to_date_player['rating']}{up_to_date_player['rating_type']} {up_to_date_player['ffe_category']}{up_to_date_player['gender']}] not pre-registered (licence type: {up_to_date_player['ffe_licence_type']}).')
            else:
                print(f'{player['comment']}: [{player['last_name']} {player['first_name']} {player['rating']}{player['rating_type']} {player['ffe_category']}{player['gender']}] not found in the database.')
        if players:
            with open(csv_file, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=list(players[0].keys()))
                writer.writeheader()
                writer.writerows(players)
            print(f'{len(players)} written to [{csv_file.name}], {len(self.players_by_ffe_id) - len(players)} skipped.')
