"""
Fetch the French schools abroad from the yearly arrêté fixing the list of the
établissements d'enseignement français à l'étranger homologués, through the
Légifrance API (https://piste.gouv.fr).
"""

import html
import os
import re
from dataclasses import dataclass
from typing import Any

import requests

from downloader import DownloadUnavailable

OAUTH_URL = 'https://oauth.piste.gouv.fr/api/oauth/token'
API_URL = 'https://api.piste.gouv.fr/dila/legifrance/lf-engine-app'
TIMEOUT = 60

# The arrêté is republished each year under this title. The ones amending it
# in the course of the year ("Arrêté du ... modifiant l'arrêté du ... fixant la
# liste...") replace its whole annex.
TITLE_SEARCH = 'fixant liste établissements enseignement français étranger homologués'
LIST_TITLE_END = (
    r'fixant la liste des (écoles et des )?établissements '
    r"d'enseignement français à l'étranger homologués"
)
YEARLY_TITLE_PATTERN = re.compile(
    rf'^Arrêté du (?P<date>(?:(?! modifiant ).)+?) {LIST_TITLE_END}'
)
AMENDING_TITLE_PATTERN = re.compile(
    rf"^Arrêté du .+? modifiant l'arrêté du (?P<date>.+?) {LIST_TITLE_END}"
)

UAI_PATTERN = re.compile(r'^\d{7}[A-Z]$')


class LegifranceFormatError(DownloadUnavailable):
    """Légifrance answered, but not with the arrêté or the table expected —
    the code needs adapting, which retrying won't fix."""


@dataclass(frozen=True)
class SchoolAbroad:
    country: str
    city: str
    name: str
    uai: str
    levels: str


class LegifranceClient:
    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token: str | None = None

    @classmethod
    def from_environment(cls) -> 'LegifranceClient | None':
        """The client configured by PISTE_CLIENT_ID and PISTE_CLIENT_SECRET, or
        None when they are not set."""
        client_id = os.environ.get('PISTE_CLIENT_ID')
        client_secret = os.environ.get('PISTE_CLIENT_SECRET')
        if not client_id or not client_secret:
            return None
        return cls(client_id, client_secret)

    def _authenticate(self) -> str:
        if self.token is None:
            response = self._send(
                OAUTH_URL,
                data={
                    'grant_type': 'client_credentials',
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'scope': 'openid',
                },
            )
            self.token = response['access_token']
        return self.token

    def _call(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._send(
            f'{API_URL}{path}',
            json=body,
            headers={
                'Authorization': f'Bearer {self._authenticate()}',
                'Accept': 'application/json',
            },
        )

    @staticmethod
    def _send(url: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = requests.post(url, timeout=TIMEOUT, **kwargs)
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as error:
            raise DownloadUnavailable(f'Légifrance request to [{url}] failed: {error}')

    def latest_list_text_id(self) -> tuple[str, str]:
        """The id and title of the text holding the current list: the latest
        yearly arrêté, or the latest arrêté amending it."""
        results = self._call(
            '/search',
            {
                'fond': 'JORF',
                'recherche': {
                    'champs': [
                        {
                            'typeChamp': 'TITLE',
                            'criteres': [
                                {
                                    'typeRecherche': 'TOUS_LES_MOTS_DANS_UN_CHAMP',
                                    'valeur': TITLE_SEARCH,
                                    'operateur': 'ET',
                                }
                            ],
                            'operateur': 'ET',
                        }
                    ],
                    'filtres': [{'facette': 'NATURE', 'valeurs': ['ARRETE']}],
                    'pageNumber': 1,
                    'pageSize': 20,
                    'operateur': 'ET',
                    'sort': 'SIGNATURE_DATE_DESC',
                    'typePagination': 'DEFAUT',
                },
            },
        ).get('results', [])
        # Newest first, so the first yearly arrêté is the current one and the
        # first amendment of it, the latest.
        titles = [
            (title['cid'], _strip_tags(title.get('title', '')))
            for result in results
            for title in result.get('titles', [])
        ]
        yearly = next(
            (
                (cid, text, match['date'])
                for cid, text in titles
                if (match := YEARLY_TITLE_PATTERN.match(text))
            ),
            None,
        )
        if yearly is None:
            raise LegifranceFormatError(
                'No arrêté fixing the list of French schools abroad found.'
            )
        yearly_cid, yearly_text, yearly_date = yearly
        for cid, text in titles:
            match = AMENDING_TITLE_PATTERN.match(text)
            if match and match['date'] == yearly_date:
                return cid, text
        return yearly_cid, yearly_text

    def schools_abroad(self) -> tuple[str, list[SchoolAbroad]]:
        """The title of the latest arrêté and the schools listed in its annex."""
        text_id, title = self.latest_list_text_id()
        text = self._call('/consult/jorf', {'textCid': text_id})
        schools: list[SchoolAbroad] = []
        for article in _articles(text):
            for row in re.findall(
                r'<tr[^>]*>(.*?)</tr>', article.get('content') or '', re.S
            ):
                cells = [
                    _strip_tags(cell)
                    for cell in re.findall(r'<t[dh][^>]*>(.*?)</t[dh]>', row, re.S)
                ]
                # Pays, Ville, Nom d'établissement, UAI, Niveaux d'enseignement,
                # Classes homologuées, Remarques; the header row has no UAI.
                if len(cells) < 5 or not UAI_PATTERN.match(cells[3]):
                    continue
                schools.append(
                    SchoolAbroad(
                        country=cells[0],
                        city=cells[1],
                        name=cells[2],
                        uai=cells[3],
                        levels='' if cells[4] == 'n/a' else cells[4],
                    )
                )
        if not schools:
            raise LegifranceFormatError(f'No school found in [{title}].')
        return title, schools


def _articles(node: dict[str, Any]) -> list[dict[str, Any]]:
    articles = list(node.get('articles') or [])
    for section in node.get('sections') or []:
        articles.extend(_articles(section))
    return articles


def _strip_tags(value: str) -> str:
    return re.sub(r'\s+', ' ', html.unescape(re.sub(r'<[^>]+>', ' ', value))).strip()
