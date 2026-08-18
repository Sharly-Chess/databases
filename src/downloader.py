import json
import os
import time
from abc import ABC
from enum import StrEnum, auto
from http import HTTPMethod
from pathlib import Path
from random import randrange, shuffle
from typing import Literal
from urllib.parse import urlparse, urlsplit

from httpdate import httpdate_to_unixtime, unixtime_to_httpdate
from requests import Response, get, head
from requests.exceptions import RequestException


class DownloadUnavailable(RuntimeError):
    """The source could not be reached (timeout/connection error) after retries.

    Raised so the workflow can treat a transient outage as "no update this run"
    rather than a hard failure — FIDE intermittently drops CI runner IPs.
    """


class SourceDataUnchanged(RuntimeError):
    """The source data has not changed."""


class ProxyUnavailable(RuntimeError):
    """No proxy available."""


class ProxyMode(StrEnum):
    # Never use a proxy, only direct connections
    NEVER = auto()
    # Use a proxy after a failure occured
    AFTER_FAILURE = auto()
    # Always use a proxy (no direct connection)
    ALWAYS = auto()


class Downloader(ABC):
    """An HTTP/HTTPS downloader class."""

    def __init__(
        self,
    ):
        super().__init__()
        # Sent as a precaution: some servers reject the default python-requests
        # User-Agent. Not the cause of the observed connect timeouts (those happen
        # before any request is sent), just harmless defensive hygiene.
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36',
        }
        # The connect and download timeouts
        self.timeouts: tuple[int, int] = (5, 60)
        # this default value may be capped by the number of available proxies
        self.default_max_attempts: int = 10
        # the delay between retries, not used when using proxies
        self.default_retry_delay: int = 30
        # the free proxies downloaded from various sites, for each scheme
        self.possible_proxies_per_scheme: dict[str, list[str]] = {}
        # the proxy to use, for each scheme
        self.proxy_per_scheme: dict[str, str] = {}

    def __get_ip_locate_proxy_list_for_scheme(
        self,
        scheme: str,
    ) -> list[str]:
        """Returns a list of proxies for a given scheme based on iplocate."""
        proxies_url: str = f'https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/{scheme}.txt'
        print(f'Downloading proxies from [{proxies_url}]...')
        try:
            response, _ = self._get_url_response(
                proxies_url,
                method=HTTPMethod.GET,
                silent=True,
                max_attempts=1,
            )
        except DownloadUnavailable as error:
            print(f'::warning:: Could not get [{proxies_url}]: {error}.')
            return []
        content: str = response.content.decode()
        proxy_list: list[str] = content.splitlines()
        print(f'Downloaded {len(proxy_list)} proxies.\n{'\n'.join(f'- {proxy}' for proxy in proxy_list)}')
        return proxy_list

    def __get_geonode_proxy_list_for_scheme(
        self,
        scheme: str,
    ) -> list[str]:
        """Returns a list of proxies for a given scheme based on https://geonode.com/free-proxy-list."""
        proxies_url: str = f'https://proxylist.geonode.com/api/proxy-list?protocols={scheme}&page=1&limit=500&sort_by=responseTime&sort_type=asc'
        print(f'Downloading proxies from [{proxies_url}]...')
        try:
            response, _ = self._get_url_response(
                proxies_url,
                method=HTTPMethod.GET,
                silent=True,
                max_attempts=1,
            )
        except DownloadUnavailable as error:
            print(f'::warning:: Could not get [{proxies_url}]: {error}.')
            return []
        content: str = response.content.decode()
        try:
            data: dict[str, list[dict[str, str]]] = json.loads(content)
        except json.JSONDecodeError as error:
            raise ProxyUnavailable(f'Invalid response: {error}.')
        proxy_list: list[str] = [
            f'{line['ip']}:{line['port']}'
            for line in data['data']
        ]
        print(f'Downloaded {len(proxy_list)} proxies.\n{'\n'.join(f'- {proxy}' for proxy in proxy_list)}')
        return proxy_list

    def _get_proxy_list_for_scheme(
        self,
        scheme: str,
    ) -> list[str]:
        """Returns a list of proxies for a given scheme."""
        proxies: list[str] = self.__get_geonode_proxy_list_for_scheme(scheme) + self.__get_ip_locate_proxy_list_for_scheme(scheme)
        shuffle(proxies)
        return proxies

    def _get_proxy_config_for_scheme(
        self,
        scheme: str,
        proxy_mode: ProxyMode,
        renew_proxy: bool,
    ) -> dict[str, str] | None:
        """Returns the proxy config to use for a given scheme, or None."""
        if proxy_mode in [ProxyMode.NEVER, ProxyMode.AFTER_FAILURE, ]:
            return None

        # if an env var is supplied, always use it.
        if system_proxy := os.environ.get('DOWNLOAD_PROXY'):
            return {
                scheme: system_proxy,
            }

        # if env var is not supplied, then use a random free proxy
        if renew_proxy or scheme not in self.proxy_per_scheme:
            if scheme in self.proxy_per_scheme:
                del self.proxy_per_scheme[scheme]

            if scheme not in self.possible_proxies_per_scheme:
                # download the list of possible proxies only once
                print(f'No proxy configured for scheme [{scheme}].')
                self.possible_proxies_per_scheme[scheme] = self._get_proxy_list_for_scheme(scheme)
                if not self.possible_proxies_per_scheme[scheme]:
                    raise ProxyUnavailable('Proxies list is empty.')
                print(f'{len(self.possible_proxies_per_scheme[scheme])} proxies read.')

            possible_proxies: list[str] = self.possible_proxies_per_scheme[scheme]
            first: int = randrange(len(possible_proxies))
            # print(f'Testing proxies (from #{first})...')
            for num in range(len(possible_proxies)):
                proxy: str = possible_proxies[(num + first) % len(possible_proxies)]
                try:
                    test_url: str = f'{scheme}://api.iplocate.io/ip'
                    #print(f'Testing proxy [{proxy}] on URL [{test_url}]...')
                    self._get_url_response(
                        test_url,
                        method=HTTPMethod.GET,
                        silent=True,
                    )
                    self.proxy_per_scheme[scheme] = proxy
                    print(f'Set proxy [{proxy}] for scheme [{scheme}].')
                    break
                except DownloadUnavailable as error:
                    print(f'Proxy #{proxy} [{proxy}] failed: {error}.')
                    pass
            if not self.proxy_per_scheme[scheme]:
                raise ProxyUnavailable('All the proxies tested failed.')
        return {
            scheme: self.proxy_per_scheme[scheme],
        }

    def _get_proxies_count_for_scheme(
        self,
        scheme: str,
        proxy_mode: ProxyMode,
    ) -> int:
        """Returns the maximum number of proxies for the scheme (will cap the number of download attempts)."""
        proxy_config_by_scheme: dict[str, str] | None = self._get_proxy_config_for_scheme(scheme, proxy_mode, renew_proxy=False)
        if proxy_config_by_scheme and scheme in proxy_config_by_scheme:
            return len(proxy_config_by_scheme[scheme])
        else:
            return 0

    def _get_url_response(
        self,
        url: str,
        method: Literal[HTTPMethod.GET, HTTPMethod.HEAD, ],
        max_attempts: int | None = None,
        retry_delay: int | None = None,
        proxy_mode: ProxyMode = ProxyMode.NEVER,
        silent: bool = False,
    ) -> tuple[Response, ProxyMode]:
        """Performs a GET or HEAD request to the specified URL and returns the response.
        The retry delay (in seconds) is doubled after each failed attempt.
        When anonymize is True, a proxy is used (and changed at each retry if not the system proxy)."""
        if not silent:
            if method == HTTPMethod.GET:
                print('Downloading content...')
            else:
                print('Downloading information...')
        scheme: str = urlparse(url).scheme
        retry_delay = retry_delay or self.default_retry_delay
        attempt: int = 1
        while True:
            request_max_attempts = max_attempts or self.default_max_attempts
            proxies_count: int = self._get_proxies_count_for_scheme(scheme, proxy_mode)
            if proxies_count:
                request_max_attempts = min(
                    request_max_attempts,
                    proxies_count,
                )
            try:
                function = get if method == HTTPMethod.GET else head
                return function(
                    url,
                    allow_redirects=True,
                    timeout=self.timeouts,
                    headers=self.headers,
                    proxies=self._get_proxy_config_for_scheme(scheme, proxy_mode, renew_proxy=attempt > 1),
                ), proxy_mode
            except RequestException as error:
                if attempt > request_max_attempts:
                    print(f'Download attempt #{attempt} failed ({error}), aborting.')
                    break
                match proxy_mode:
                    case ProxyMode.NEVER:
                        print(f'Download attempt #{attempt} failed ({error}); retrying in {retry_delay}s...')
                        time.sleep(retry_delay)
                        retry_delay *= 2
                    case ProxyMode.AFTER_FAILURE:
                        proxy_mode = ProxyMode.ALWAYS
                        print(f'Download attempt #{attempt} failed ({error}); retrying using a proxy...')
                    case ProxyMode.ALWAYS:
                        print(f'Download attempt #{attempt} failed ({error}); retrying using another proxy...')
                attempt += 1
        raise DownloadUnavailable(
            f'Download failed after {request_max_attempts} attempts.'
        )

    def _download_file(
        self,
        url: str,
        target_dir: Path,
        if_modified_since: int | None = None,
        target_filename: str | None = None,
        max_attempts: int | None = None,
        retry_delay: int | None = None,
        proxy_mode: ProxyMode = ProxyMode.NEVER,
    ) -> Path:
        """Download a file from the specified URL.
        if *if_modified_since* is not None:
        - a HEAD request is performed to get the last modification date of the ressource.
        - if the HEAD request fails (e.g. HTTP error, no last modification date, ...), a *DownloadUnavailable* exception is raised.
        - if the last modification date of the ressource is older than *if_modified_since* a *SourceDataUnchanged* exception is raised.
        - otherwise the download is performed and the path of the resulting file is returned (a *DownloadUnavailable* exception is raised on failure).
        """
        if if_modified_since:
            head_response, proxy_mode = self._get_url_response(
                url,
                method=HTTPMethod.HEAD,
                max_attempts=max_attempts,
                retry_delay=retry_delay,
                proxy_mode=proxy_mode,
            )
            last_modified_header: str = 'Last-Modified'
            last_modified: str = head_response.headers.get(last_modified_header, '')
            if not last_modified:
                raise DownloadUnavailable(f'Header [{last_modified_header}] not found.')
            print(f'{last_modified_header}: {last_modified}')
            last_modified_timestamp: int = httpdate_to_unixtime(last_modified)
            if_modified_since_str: str = unixtime_to_httpdate(if_modified_since)
            if last_modified_timestamp < if_modified_since:
                raise SourceDataUnchanged(f'URL is unchanged since [{if_modified_since_str}].')
            print(f'URL has changed since [{if_modified_since_str}].')

        get_response, proxy_mode = self._get_url_response(
            url,
            method=HTTPMethod.GET,
            max_attempts=max_attempts,
            retry_delay=retry_delay,
            proxy_mode=proxy_mode,
            silent=not if_modified_since,
        )

        if get_response.status_code != 200:
            raise DownloadUnavailable(f'Download failed with HTTP code {get_response.status_code}')

        content_length: int = int(get_response.headers.get('content-length', 0))
        if content_length > 100 * 1_024:
            print(f'Received {content_length / 1_048_576:.1f} MB.')
        elif content_length:
            print(f'Received {content_length / 1_024:.1f} KB.')
        else:
            print('Downloaded complete.')

        print('Reading data...')
        if not target_filename:
            target_filename = urlsplit(url).path.split('/')[-1]
        target_file = target_dir / target_filename
        read: int = 0
        with open(target_file, 'wb') as f:
            for chunk in get_response.iter_content(chunk_size=1024 * 1024):
                f.write(chunk)
                read += len(chunk)
        if content_length:
            print('Done.')
        elif read > 100 * 1_024:
            print(f'Read {read / 1_048_576:.1f} MB.')
        else:
            print(f'Read {read / 1_024:.1f} KB.')
        if not target_file.exists():
            raise DownloadUnavailable('No data read.')
        return target_file
