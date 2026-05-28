from typing import Any


class PlayerContainer:
    def __init__(self):
        self.players_by_ffe_id: dict[int, dict[str, Any]] = {}

    @property
    def players(self) -> list[dict[str, Any]]:
        return list(self.players_by_ffe_id.values())

    def add_player(self, player: dict[str, Any]):
        ffe_id: int = player['ffe_id']
        if ffe_id not in self.players_by_ffe_id:
            self.players_by_ffe_id[ffe_id] = player

    def add_players(self, players: list[dict[str, Any]]):
        for player in players:
            self.add_player(player)
