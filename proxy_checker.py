#!/usr/bin/env python3
"""Scrape public proxy lists and save only proxies that pass a HTTP test.

The input file contains one HTTP(S) source URL per line.  Proxy candidates found
in each response are normalised to one of these output forms:

    socks4://HOST:PORT
    socks5://HOST:PORT
    socks5://USER:PASSWORD@HOST:PORT
    http://HOST:PORT
    http://USER:PASSWORD@HOST:PORT

HTTP proxies are checked through one shared aiohttp session.  SOCKS proxies need
a different connector for each proxy, so they are checked in their own short-
lived sessions.  A bounded worker queue keeps memory use predictable even for
large proxy lists.
"""

import argparse
import asyncio
import html
import ipaddress
import logging
import math
import os
import re
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import List, Optional, Sequence, Set, Tuple
from urllib.parse import quote, unquote, urlsplit

import aiohttp
from aiohttp_socks import ProxyConnector
from tqdm import tqdm


DEFAULT_TEST_URL = "https://api.ipify.org?format=json"
DEFAULT_TIMEOUT = 5.0
MAX_SOURCE_BYTES = 10 * 1024 * 1024  # Do not accidentally load an unbounded page.
USER_AGENT = "Proxy-King-Checker/1.0 (+local connectivity testing)"

LOGGER = logging.getLogger("proxy_checker")

# This intentionally accepts both complete proxy URLs and bare HOST:PORT values
# embedded in text or HTML.  It does not accept arbitrary URL paths, because a
# saved proxy must be just a scheme, optional credentials, host, and port.
PROXY_PATTERN = re.compile(
    r"""
    (?<![a-z0-9_.@-])
    (?:(?P<scheme>https?|socks4a?|socks5h?)://)?
    (?:(?P<username>[^\s:@/]+):(?P<password>[^\s@/]+)@)?
    (?P<host>
        (?:\d{1,3}\.){3}\d{1,3} |
        \[[0-9a-f:.]+\] |
        (?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
           (?:[a-z][a-z0-9-]{0,62})) |
        localhost
    )
    \s*:\s*(?P<port>\d{1,5})(?![a-z0-9])
    """,
    re.IGNORECASE | re.VERBOSE,
)

DOMAIN_PATTERN = re.compile(
    r"(?i)^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)

CheckedProxy = Tuple[str, bool, Optional[float]]


def configure_logging(log_file: str) -> None:
    """Write detailed, timestamped diagnostics without flooding stdout."""
    log_path = Path(log_file).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    LOGGER.setLevel(logging.DEBUG)
    LOGGER.propagate = False
    LOGGER.handlers.clear()

    handler = RotatingFileHandler(
        log_path, maxBytes=5 * 1024 * 1024, backupCount=2, encoding="utf-8"
    )
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    LOGGER.addHandler(handler)


def _http_url(value: str) -> str:
    """Argparse validator for URLs which aiohttp can fetch."""
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise argparse.ArgumentTypeError("must be an absolute http:// or https:// URL")
    return value


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= number <= 1000:
        raise argparse.ArgumentTypeError("must be between 1 and 1000")
    return number


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return number


def _non_negative_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("must be a finite number that is zero or greater")
    return number


def read_sources(file_path: str) -> List[str]:
    """Read valid, de-duplicated source URLs while preserving their order.

    Empty lines and lines beginning with ``#`` are ignored.  Invalid entries are
    logged and skipped rather than aborting a long run.
    """
    sources: List[str] = []
    seen: Set[str] = set()

    with Path(file_path).expanduser().open("r", encoding="utf-8") as source_file:
        for line_number, line in enumerate(source_file, start=1):
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            try:
                _http_url(url)
            except argparse.ArgumentTypeError:
                LOGGER.warning("Ignoring invalid source at line %d: %r", line_number, url)
                continue
            if url not in seen:
                seen.add(url)
                sources.append(url)

    return sources


def _valid_host(host: str) -> bool:
    """Validate an IPv4/IPv6 literal, localhost, or conventional DNS name."""
    if host.lower() == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(DOMAIN_PATTERN.fullmatch(host))


def _quote_credential(value: str) -> str:
    """Return a safe URL userinfo component while preserving its meaning."""
    # Decode an existing percent escape once, then write one canonical escape.
    # '@' and '/' must be escaped so they cannot alter the proxy URL structure.
    return quote(unquote(value), safe="!$&'()*+,;=:")


def normalize_proxy(raw: str) -> Optional[str]:
    """Convert a candidate to an allowed output proxy URL, or return ``None``.

    Bare addresses default to HTTP.  ``https://`` is normalised to ``http://``:
    many public lists use "HTTPS" to mean an HTTP CONNECT proxy capable of
    reaching HTTPS destinations, while the requested output formats permit only
    ``http://``.  SOCKS4a and SOCKS5h are similarly represented by the allowed
    socks4 and socks5 schemes.
    """
    value = raw.strip(" \t\r\n\"'`,;(){}<>")
    # Sources sometimes place whitespace around the address separator in HTML.
    value = re.sub(r"\s*:\s*", ":", value)
    if not value:
        return None

    candidate_url = value if "://" in value else "http://" + value
    try:
        parsed = urlsplit(candidate_url)
        scheme = parsed.scheme.lower()
        if scheme in {"http", "https"}:
            output_scheme = "http"
        elif scheme in {"socks4", "socks4a"}:
            output_scheme = "socks4"
        elif scheme in {"socks5", "socks5h"}:
            output_scheme = "socks5"
        else:
            return None

        # Proxy URLs have no meaningful path, query, or fragment.  A trailing
        # slash is harmless and is removed in the canonical output.
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return None
        if not parsed.hostname:
            return None

        host = parsed.hostname
        port = parsed.port  # Accessing this property also rejects malformed ports.
        if port is None or not 1 <= port <= 65535 or not _valid_host(host):
            return None

        username, password = parsed.username, parsed.password
        if (username is None) != (password is None):
            return None
        # SOCKS4 does not use username/password authentication, and an
        # authenticated SOCKS4 URL is not one of the permitted output forms.
        if output_scheme == "socks4" and username is not None:
            return None

        # IPv6 literals need brackets when converted back to URL form.
        display_host = "[%s]" % host if ":" in host else host
        credentials = ""
        if username is not None and password is not None:
            credentials = "%s:%s@" % (
                _quote_credential(username),
                _quote_credential(password),
            )

        return "%s://%s%s:%d" % (output_scheme, credentials, display_host, port)
    except (TypeError, ValueError):
        return None


def _redact_proxy(proxy: str) -> str:
    """Avoid writing proxy credentials to diagnostic logs."""
    try:
        parsed = urlsplit(proxy)
        if parsed.username is None:
            return proxy
        host = parsed.hostname or "unknown-host"
        host = "[%s]" % host if ":" in host else host
        port = (":%d" % parsed.port) if parsed.port is not None else ""
        return "%s://***:***@%s%s" % (parsed.scheme, host, port)
    except (TypeError, ValueError):
        return "<unparseable proxy>"


async def _read_response_limited(response: aiohttp.ClientResponse) -> str:
    """Read source content while enforcing a modest maximum response size."""
    content_length = response.content_length
    if content_length is not None and content_length > MAX_SOURCE_BYTES:
        raise ValueError(
            "source response is too large (%d bytes; maximum is %d)"
            % (content_length, MAX_SOURCE_BYTES)
        )

    chunks: List[bytes] = []
    total = 0
    async for chunk in response.content.iter_chunked(64 * 1024):
        total += len(chunk)
        if total > MAX_SOURCE_BYTES:
            raise ValueError("source response exceeded the maximum size")
        chunks.append(chunk)

    encoding = response.charset or "utf-8"
    return b"".join(chunks).decode(encoding, errors="replace")


async def scrape_proxies(
    url: str, session: aiohttp.ClientSession, timeout: float
) -> Set[str]:
    """Fetch one source URL and return raw proxy-looking candidates from it.

    Network and parsing failures are contained here so one unavailable source
    never prevents the remaining source list from being processed.
    """
    try:
        request_timeout = aiohttp.ClientTimeout(total=timeout)
        async with session.get(
            url, timeout=request_timeout, allow_redirects=True, max_redirects=5
        ) as response:
            if response.status != 200:
                LOGGER.warning("Source returned HTTP %d: %s", response.status, url)
                return set()
            body = await _read_response_limited(response)
    except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError, ValueError) as exc:
        LOGGER.warning("Could not scrape source %s: %s", url, exc)
        return set()
    except Exception:
        LOGGER.exception("Unexpected error while scraping source %s", url)
        return set()

    # html.unescape handles entities such as &#58; in otherwise plain HTML.
    candidates = {match.group(0) for match in PROXY_PATTERN.finditer(html.unescape(body))}
    LOGGER.info("Scraped %d raw candidate(s) from %s", len(candidates), url)
    return candidates


async def scrape_all_sources(
    sources: Sequence[str], timeout: float, source_concurrency: int
) -> List[Set[str]]:
    """Scrape sources concurrently, with a separate bound from proxy workers."""
    connector = aiohttp.TCPConnector(
        limit=source_concurrency,
        limit_per_host=source_concurrency,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
    )
    headers = {"User-Agent": USER_AGENT, "Accept": "text/plain,text/html,*/*;q=0.1"}
    semaphore = asyncio.Semaphore(source_concurrency)

    async with aiohttp.ClientSession(
        connector=connector, headers=headers, trust_env=False
    ) as session:

        async def fetch_one(source_url: str) -> Set[str]:
            async with semaphore:
                return await scrape_proxies(source_url, session, timeout)

        return await asyncio.gather(*(fetch_one(url) for url in sources))


async def _successful_response(
    session: aiohttp.ClientSession, test_url: str, proxy: Optional[str]
) -> bool:
    """Return true only for a 200 response containing at least one byte."""
    request_options = {"allow_redirects": False}
    if proxy is not None:
        request_options["proxy"] = proxy

    async with session.get(test_url, **request_options) as response:
        if response.status != 200:
            return False
        # The contract requires a non-empty body.  One byte is sufficient and
        # avoids downloading an unexpectedly large test response.
        return bool(await response.content.read(1))


async def check_proxy(
    proxy: str,
    test_url: str,
    timeout: float,
    *,
    http_session: Optional[aiohttp.ClientSession] = None,
    retries: int = 0,
) -> CheckedProxy:
    """Check one proxy and return ``(proxy, is_working, speed_seconds)``.

    ``http_session`` lets callers reuse connections for HTTP proxies.  SOCKS
    connectors are necessarily configured with a different proxy per request,
    so they use an isolated session and connector.  A failed proxy is retried at
    most ``retries`` times and is then reported as not working.
    """
    attempts = retries + 1
    scheme = urlsplit(proxy).scheme.lower()
    timeout_config = aiohttp.ClientTimeout(total=timeout)

    for attempt in range(1, attempts + 1):
        started = time.perf_counter()
        try:
            if scheme in {"socks4", "socks5"}:
                connector = ProxyConnector.from_url(proxy, limit=1, force_close=True)
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout_config,
                    headers={"User-Agent": USER_AGENT},
                    trust_env=False,
                ) as socks_session:
                    is_working = await _successful_response(socks_session, test_url, None)
            elif http_session is not None:
                is_working = await _successful_response(http_session, test_url, proxy)
            else:
                connector = aiohttp.TCPConnector(limit=1, force_close=True)
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout_config,
                    headers={"User-Agent": USER_AGENT},
                    trust_env=False,
                ) as one_off_session:
                    is_working = await _successful_response(one_off_session, test_url, proxy)

            elapsed = time.perf_counter() - started
            if is_working:
                return proxy, True, elapsed
            LOGGER.debug(
                "Proxy %s returned a non-200 or empty test response (attempt %d/%d)",
                _redact_proxy(proxy),
                attempt,
                attempts,
            )
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
            # Exception messages can repeat the full proxy URL, so log the error
            # class but not its message; the proxy itself is redacted above.
            LOGGER.debug(
                "Proxy %s failed on attempt %d/%d: %s",
                _redact_proxy(proxy),
                attempt,
                attempts,
                type(exc).__name__,
            )
        except Exception as exc:
            # Keep a malformed third-party proxy response from killing all workers.
            # As above, do not render exception text that might include userinfo.
            LOGGER.error(
                "Unexpected proxy-check error for %s (attempt %d/%d): %s",
                _redact_proxy(proxy),
                attempt,
                attempts,
                type(exc).__name__,
            )

    return proxy, False, None


async def check_all_proxies(
    proxies: Sequence[str],
    test_url: str,
    timeout: float,
    workers: int,
    retries: int,
    delay: float,
) -> List[CheckedProxy]:
    """Check all proxies using a bounded async worker queue and a progress bar."""
    queue: "asyncio.Queue[Optional[str]]" = asyncio.Queue()
    for proxy in proxies:
        queue.put_nowait(proxy)

    results: List[CheckedProxy] = []
    worker_count = min(workers, len(proxies))
    connector = aiohttp.TCPConnector(
        limit=worker_count,
        limit_per_host=worker_count,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
    )
    session_timeout = aiohttp.ClientTimeout(total=timeout)

    with tqdm(total=len(proxies), unit="proxy", desc="Checking", dynamic_ncols=True) as progress:
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=session_timeout,
            headers={"User-Agent": USER_AGENT},
            trust_env=False,
        ) as http_session:

            async def worker() -> None:
                while True:
                    proxy = await queue.get()
                    try:
                        if proxy is None:
                            return
                        try:
                            results.append(
                                await check_proxy(
                                    proxy,
                                    test_url,
                                    timeout,
                                    http_session=http_session,
                                    retries=retries,
                                )
                            )
                        except Exception as exc:
                            # check_proxy already handles expected request errors;
                            # this final guard protects the whole worker pool.
                            LOGGER.error(
                                "Worker failed while checking %s: %s",
                                _redact_proxy(proxy),
                                type(exc).__name__,
                            )
                            results.append((proxy, False, None))
                        finally:
                            progress.update(1)

                        # A short per-worker pause can be useful when checking a
                        # public test endpoint.  The default is deliberately zero.
                        if delay and not queue.empty():
                            await asyncio.sleep(delay)
                    finally:
                        queue.task_done()

            tasks = [asyncio.create_task(worker()) for _ in range(worker_count)]
            try:
                await queue.join()
            finally:
                # Sentinels let each worker exit normally before the session closes.
                for _ in tasks:
                    queue.put_nowait(None)
                await asyncio.gather(*tasks, return_exceptions=True)

    return results


def save_working_proxies(
    checked: Sequence[CheckedProxy], output_file: str, sort_order: str
) -> List[str]:
    """Atomically write only successful proxies and return the written values."""
    working = [(proxy, speed) for proxy, ok, speed in checked if ok]
    if sort_order == "alphabetical":
        working.sort(key=lambda item: item[0])
    elif sort_order == "speed":
        working.sort(key=lambda item: (item[1] is None, item[1], item[0]))

    proxy_lines = [proxy for proxy, _ in working]
    destination = Path(output_file).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)

    # Replacing the completed temporary file prevents consumers from reading a
    # half-written proxy list if this program is interrupted during output.
    with NamedTemporaryFile(
        "w", encoding="utf-8", dir=str(destination.parent), delete=False
    ) as temporary_file:
        temporary_file.write("\n".join(proxy_lines))
        if proxy_lines:
            temporary_file.write("\n")
        temporary_name = temporary_file.name
    os.replace(temporary_name, destination)
    return proxy_lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scrape proxy sources and save only proxies that pass a GET test."
    )
    parser.add_argument(
        "--sources",
        default="proxy_sources.txt",
        help="Text file containing one HTTP(S) proxy-source URL per line (default: %(default)s)",
    )
    parser.add_argument(
        "--test-url",
        type=_http_url,
        default=DEFAULT_TEST_URL,
        help="HTTP(S) URL requested through every proxy (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_TIMEOUT,
        help="Total seconds allowed for each request (default: %(default)s)",
    )
    parser.add_argument(
        "--threads",
        "--workers",
        dest="workers",
        type=_positive_int,
        default=50,
        help="Maximum concurrent proxy checks, from 1 to 1000 (default: %(default)s)",
    )
    parser.add_argument(
        "--source-concurrency",
        type=_positive_int,
        default=10,
        help="Maximum concurrent source downloads (default: %(default)s)",
    )
    parser.add_argument(
        "--source-timeout",
        type=_positive_float,
        default=20.0,
        help="Total seconds allowed for one source download (default: %(default)s)",
    )
    parser.add_argument(
        "--retries",
        type=lambda value: _non_negative_int(value, maximum=10),
        default=0,
        help="Extra attempts for each failed proxy, from 0 to 10 (default: %(default)s)",
    )
    parser.add_argument(
        "--delay",
        type=_non_negative_float,
        default=0.0,
        help="Seconds each worker pauses between checks (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        default="proxy.txt",
        help="File for working proxies (default: %(default)s)",
    )
    parser.add_argument(
        "--sort",
        choices=("alphabetical", "speed", "none"),
        default="alphabetical",
        help="Output order (default: %(default)s)",
    )
    parser.add_argument(
        "--log-file",
        default="proxy_checker.log",
        help="Diagnostic log file (default: %(default)s)",
    )
    return parser


def _non_negative_int(value: str, maximum: int) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 0 <= number <= maximum:
        raise argparse.ArgumentTypeError("must be between 0 and %d" % maximum)
    return number


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the scrape, normalisation, validation, and output pipeline."""
    parser = build_parser()
    args = parser.parse_args(argv)

    configure_logging(args.log_file)
    LOGGER.info("Starting proxy check: sources=%s test_url=%s", args.sources, args.test_url)

    try:
        sources = read_sources(args.sources)
    except OSError as exc:
        LOGGER.error("Could not read source file %s: %s", args.sources, exc)
        print("Error: could not read %s: %s" % (args.sources, exc), file=sys.stderr)
        return 2

    if not sources:
        LOGGER.warning("No valid source URLs were found in %s", args.sources)
        print("No valid source URLs found in %s." % args.sources, file=sys.stderr)
        return 2

    print("Scraping %d source(s)..." % len(sources))
    raw_sets = asyncio.run(
        scrape_all_sources(sources, args.source_timeout, args.source_concurrency)
    )
    total_scraped = sum(len(raw_set) for raw_set in raw_sets)

    normalized: Set[str] = set()
    invalid_count = 0
    for raw_set in raw_sets:
        for raw in raw_set:
            proxy = normalize_proxy(raw)
            if proxy is None:
                invalid_count += 1
            else:
                normalized.add(proxy)

    proxies = sorted(normalized)
    LOGGER.info(
        "Found %d raw candidate(s), %d unique normalised proxy/proxies, %d invalid",
        total_scraped,
        len(proxies),
        invalid_count,
    )

    if proxies:
        checked = asyncio.run(
            check_all_proxies(
                proxies,
                args.test_url,
                args.timeout,
                args.workers,
                args.retries,
                args.delay,
            )
        )
    else:
        checked = []

    written = save_working_proxies(checked, args.output, args.sort)
    checked_count = len(checked)
    summary = (
        "Summary: scraped=%d, unique=%d, checked=%d, working=%d\n"
        "Working proxies written to %s"
        % (total_scraped, len(proxies), checked_count, len(written), args.output)
    )
    LOGGER.info(summary.replace("\n", " | "))
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
