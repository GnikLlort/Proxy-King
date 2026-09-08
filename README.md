# Proxy-King

`proxy_checker.py` scrapes proxy candidates from HTTP(S) URLs, checks them with a
configurable GET request, and writes only working entries to `proxy.txt`.

## Install

Python 3.8 or newer is required.

```bash
python -m pip install -r requirements.txt
```

## Use

Create `proxy_sources.txt` with one source URL per line. Blank lines and lines
beginning with `#` are ignored.

```bash
python proxy_checker.py \
  --sources proxy_sources.txt \
  --test-url 'https://api.ipify.org?format=json' \
  --timeout 5 \
  --threads 100 \
  --output proxy.txt
```

The checker supports HTTP, SOCKS4, SOCKS4a, SOCKS5, and SOCKS5h candidates.
Bare `HOST:PORT` entries default to HTTP. The output is normalized to the
requested `http://`, `socks4://`, or `socks5://` forms and includes only
responses with status `200` and a non-empty body. Detailed failures are written
to `proxy_checker.log`; credentials are redacted from log messages.

Run `python proxy_checker.py --help` for worker, retry, delay, source-timeout,
log-file, and output-order options.
