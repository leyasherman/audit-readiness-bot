"""Dependency supply-chain checks: typosquats and AI-hallucinated package names ("slopsquatting").

AI coding assistants regularly emit dependency names that are almost right (`reqeusts`), that are an
import name rather than the published package (`sklearn`, `cv2`), or that don't exist at all. Attackers
register exactly those names; whatever they upload runs at `pip install` / `npm install` time.

Offline (default, deterministic, used by the commit gate):
  1. publicly reported squat/hallucination names
  2. import name used as package name (sklearn -> scikit-learn)
  3. separator / look-alike variants of a popular package (crossenv -> cross-env, jeIlyfish -> jellyfish)
  4. popular name plus an impersonation affix (pytorch -> torch, requests3 -> requests)
  5. one keystroke from a popular package (reqeusts -> requests), two for long names
Online (`--online` or AUDITBOT_ONLINE=1; any network error is ignored so the gate never breaks):
  6. name does not exist on the registry -> hallucinated, free for anyone to register
  7. package first published < 90 days ago -> verify the publisher before installing
"""
from __future__ import annotations

import json
import os
import re
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------- reference data
# Widely used packages (normalized names). A dependency that is NOT in this set but sits right next to
# one of them is the typosquat signal. Popular names themselves are never flagged.
POPULAR = {
    "pypi": set("""
boto3 botocore urllib3 requests setuptools certifi charset-normalizer idna typing-extensions python-dateutil s3transfer
packaging aiobotocore six numpy pyyaml s3fs fsspec pip cryptography grpcio grpcio-status grpcio-tools google-api-core cffi
pycparser pandas importlib-metadata attrs pyasn1 pyasn1-modules protobuf rsa zipp click jmespath wheel platformdirs pydantic
pydantic-core pydantic-settings jinja2 markupsafe pytz colorama awscli filelock virtualenv tomli tomlkit toml pyjwt
googleapis-common-protos wrapt cachetools pluggy pytest pytest-cov pytest-mock pytest-asyncio pytest-xdist google-auth
google-auth-httplib2 google-api-python-client google-cloud-storage google-cloud-core sqlalchemy psutil pyparsing greenlet
aiohttp multidict yarl frozenlist aiosignal iniconfig exceptiongroup docutils requests-oauthlib requests-toolbelt oauthlib
pyarrow scipy tqdm soupsieve beautifulsoup4 werkzeug flask itsdangerous h11 httpx httpcore anyio sniffio decorator pillow
lxml isodate openpyxl et-xmlfile tzdata pyopenssl more-itertools websocket-client websockets distlib coverage mypy
mypy-extensions regex rich pygments markdown-it-py mdurl sortedcontainers redis psycopg psycopg2 psycopg2-binary pymysql
mysql-connector-python matplotlib kiwisolver cycler fonttools contourpy scikit-learn scikit-image joblib threadpoolctl
django djangorestframework django-cors-headers fastapi starlette uvicorn gunicorn celery kombu billiard vine amqp paramiko
bcrypt pynacl docker kubernetes azure-core azure-identity azure-storage-blob msal pymongo elasticsearch marshmallow alembic
mako networkx sympy mpmath torch torchvision torchaudio tensorflow keras transformers tokenizers huggingface-hub
safetensors datasets accelerate openai anthropic langchain langchain-core langchain-community langchain-openai tiktoken
nltk spacy opencv-python opencv-python-headless selenium playwright black flake8 pylint isort ruff pre-commit tox nox
poetry pipenv setuptools-scm twine sphinx jsonschema ujson orjson simplejson python-dotenv typer loguru structlog
sentry-sdk prometheus-client opentelemetry-api opentelemetry-sdk ipython jupyter notebook ipykernel nbformat tornado
pyzmq traitlets xgboost lightgbm statsmodels seaborn plotly dash streamlit gradio boto jellyfish colorlog termcolor
tabulate xmltodict chardet arrow pendulum dateparser faker factory-boy hypothesis responses freezegun mock asyncpg
aiofiles pyspark dask polars duckdb snowflake-connector-python oracledb pyodbc ldap3 python-jose passlib authlib
flask-cors flask-sqlalchemy flask-login graphql-core ansible ansible-core fabric invoke pexpect ptyprocess pywin32
wcwidth prompt-toolkit shapely geopandas pyproj gitpython pygithub slack-sdk twilio stripe sendgrid tenacity backoff
diskcache graphviz cython numba llvmlite pybind11 cmake ninja imageio pyinstaller cattrs deprecated jsonpointer
jsonpatch httplib2 uritemplate pycryptodome pycryptodomex python-multipart email-validator dnspython ruamel-yaml
jsonpickle dill cloudpickle msgpack lz4 zstandard brotli python-magic python-docx python-pptx pyserial pymupdf
python-slugify python-socketio python-telegram-bot python-ldap pyusb levenshtein simpy scapy pytest-env pytest-django
""".split()),
    "npm": set("""
lodash react react-dom express axios chalk commander debug moment uuid tslib typescript webpack vue next eslint prettier
jest mocha chai request async bluebird underscore jquery body-parser cookie-parser cors dotenv mongoose mongodb mysql
mysql2 pg sequelize redis ioredis socket.io ws yargs minimist glob rimraf mkdirp fs-extra semver inquirer ora colors
cross-env nodemon ts-node rxjs zone.js core-js regenerator-runtime classnames prop-types styled-components redux
react-redux react-router react-router-dom immer zustand swr graphql apollo-server jsonwebtoken bcrypt bcryptjs passport
helmet morgan winston pino nodemailer multer sharp cheerio puppeteer playwright electron vite rollup esbuild parcel
postcss autoprefixer tailwindcss sass less node-fetch isomorphic-fetch cross-fetch form-data qs query-string date-fns
dayjs luxon ramda validator joi yup zod ajv chokidar concurrently husky lint-staged webpack-cli webpack-dev-server
babel-loader css-loader style-loader file-loader html-webpack-plugin ts-loader jsdom supertest sinon nock cypress vitest
karma svelte nuxt gatsby three d3 chart.js echarts highcharts leaflet mapbox-gl firebase aws-sdk stripe twilio openai
discord.js telegraf node-cron cron bull kafkajs amqplib handlebars ejs pug marked highlight.js katex deepmerge clsx
nanoid shortid crypto-js js-yaml yaml xml2js csv-parse papaparse xlsx pdfkit archiver adm-zip tar http-proxy
http-proxy-middleware express-session compression serve-static connect koa fastify prisma typeorm knex sqlite3
better-sqlite3 mime mime-types kleur picocolors ansi-styles strip-ansi string-width wrap-ansi lru-cache node-gyp nan
bindings cross-spawn execa shelljs open dotenv-expand eslint-config-prettier eslint-plugin-react color preact react-dnd
""".split()),
}

# Import name -> the package that actually publishes it. Assistants copy the import line into
# requirements; on PyPI those names are unclaimed, placeholders, or owned by someone else.
IMPORT_NAMES = {
    "sklearn": "scikit-learn", "cv2": "opencv-python", "yaml": "pyyaml", "pil": "pillow", "bs4": "beautifulsoup4",
    "dateutil": "python-dateutil", "dotenv": "python-dotenv", "jwt": "pyjwt", "magic": "python-magic",
    "docx": "python-docx", "pptx": "python-pptx", "serial": "pyserial", "usb": "pyusb", "git": "gitpython",
    "openssl": "pyopenssl", "crypto": "pycryptodome", "jose": "python-jose", "telegram": "python-telegram-bot",
    "attr": "attrs", "fitz": "pymupdf", "skimage": "scikit-image", "zmq": "pyzmq", "win32api": "pywin32",
    "ldap": "python-ldap", "slugify": "python-slugify", "multipart": "python-multipart", "socketio": "python-socketio",
}

# Publicly reported squats / hallucinations, with the package that was meant.
KNOWN_BAD = {
    "pypi": {
        "huggingface-cli": ("huggingface-hub[cli]", "a name AI assistants hallucinate; it was registered on PyPI "
                                                    "by a researcher to demonstrate slopsquatting"),
        "python3-dateutil": ("python-dateutil", "a reported malicious typosquat (2019)"),
        "jeilyfish": ("jellyfish", "a reported malicious typosquat (2019, capital I for l)"),
    },
    "npm": {
        "crossenv": ("cross-env", "a reported malicious typosquat that stole environment variables (2017)"),
    },
}

PREFIXES = ("python-", "python3-", "py-", "py", "node-")
SUFFIXES = ("-python", "-py", "py", "-js", ".js", "js", "-node", "-cli", "2", "3")
NEW_PACKAGE_DAYS = 90
ALLOW_MARK = "auditbot: allow"


def normalize(eco: str, name: str) -> str:
    n = name.strip().lower()
    return re.sub(r"[-_.]+", "-", n) if eco == "pypi" else n


def skeleton(name: str) -> str:
    """Collapse separators and look-alike characters: what a human skimming the diff would see."""
    s = re.sub(r"[-_.]", "", name.lower())
    return s.replace("rn", "m").replace("vv", "w").replace("0", "o").replace("1", "i").replace("l", "i")


def osa_distance(a: str, b: str, limit: int = 3) -> int:
    """Damerau-Levenshtein (optimal string alignment): a swapped pair of letters counts as one edit."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def offline_verdict(eco: str, name: str) -> tuple[str, str] | None:
    """(detail, suggested name) if `name` looks like a squat of something popular, else None."""
    n = normalize(eco, name)
    if eco == "npm" and n.startswith("@"):
        return None  # scoped packages are namespace-protected
    if n in KNOWN_BAD.get(eco, {}):
        good, why = KNOWN_BAD[eco][n]
        return f"'{name}' is {why}. Did you mean '{good}'?", good
    popular = POPULAR[eco]
    if n in popular:
        return None
    if eco == "pypi" and n in IMPORT_NAMES:
        good = IMPORT_NAMES[n]
        return (f"'{name}' is an import name, not the package: the library is published as '{good}'. "
                f"Installing '{name}' fetches whatever someone registered under that name. Did you mean '{good}'?"), good
    sk = skeleton(n)
    for p in sorted(popular):
        if len(p) >= 4 and skeleton(p) == sk:
            return (f"'{name}' differs from the popular package '{p}' only by separators or look-alike characters "
                    f"(typosquat pattern). Did you mean '{p}'?"), p
    for p in sorted(popular):
        if len(p) < 4:
            continue
        if any(n == pre + p for pre in PREFIXES) or any(n == p + suf for suf in SUFFIXES):
            return (f"'{name}' is the popular package '{p}' with an extra prefix/suffix, a common impersonation "
                    f"pattern. Did you mean '{p}'?"), p
    best = None
    for p in popular:
        limit = 2 if len(p) >= 12 else 1 if len(p) >= 5 else 0
        if not limit:
            continue
        d = osa_distance(n, p, limit)
        if d <= limit and (best is None or d < best[0]):
            best = (d, p)
    if best:
        d, p = best
        return (f"'{name}' is {d} keystroke{'s' if d > 1 else ''} away from the popular package '{p}' "
                f"(likely typo or typosquat). Did you mean '{p}'?"), p
    return None


# ---------------------------------------------------------------- manifest parsing

REQ_FILE = re.compile(r"(^|/)(requirements[^/]*|constraints[^/]*)\.(txt|in)$", re.I)
NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def is_manifest(path: str) -> bool:
    name = Path(path).name
    return bool(REQ_FILE.search(path)) or name in ("pyproject.toml", "package.json")


def _line_index(text: str, needle_re: str) -> int:
    m = re.search(needle_re, text)
    return m.start() if m else 0


def dependencies(path: str, text: str):
    """Yield (ecosystem, name, char_index, allowed) for each declared dependency."""
    name = Path(path).name
    if REQ_FILE.search(path):
        pos = 0
        for line in text.splitlines(keepends=True):
            body = line.split("#", 1)[0].strip()
            if body and not body.startswith("-") and "://" not in body:
                m = NAME_RE.match(body)
                if m:
                    yield "pypi", m.group(1), pos + line.find(m.group(1)), ALLOW_MARK in line
            pos += len(line)
    elif name == "pyproject.toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return
        proj = data.get("project", {})
        specs = list(proj.get("dependencies", []))
        for group in proj.get("optional-dependencies", {}).values():
            specs += list(group)
        for group in data.get("dependency-groups", {}).values():
            specs += [s for s in group if isinstance(s, str)]
        poetry = data.get("tool", {}).get("poetry", {})
        specs += [k for k in poetry.get("dependencies", {}) if k.lower() != "python"]
        for grp in poetry.get("group", {}).values():
            specs += list(grp.get("dependencies", {}))
        for spec in specs:
            m = NAME_RE.match(spec)
            if not m:
                continue
            dep = m.group(1)
            idx = _line_index(text, r"(?m)[\"']?" + re.escape(dep) + r"(?![A-Za-z0-9_-])")
            line = text[text.rfind("\n", 0, idx) + 1: text.find("\n", idx) if text.find("\n", idx) >= 0 else len(text)]
            yield "pypi", dep, idx, ALLOW_MARK in line
    elif name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        if not isinstance(data, dict):
            return
        allow = {normalize("npm", a) for a in (data.get("auditbot") or {}).get("allow", [])}
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for dep, ver in (data.get(key) or {}).items():
                if isinstance(ver, str) and re.match(r"^(file:|link:|workspace:|git|https?:)", ver):
                    continue  # local / VCS references don't come from the registry by name
                yield "npm", dep, _line_index(text, r"\"" + re.escape(dep) + r"\"\s*:"), normalize("npm", dep) in allow


# ---------------------------------------------------------------- optional registry lookup

CACHE = Path(__file__).parent.parent / ".auditbot-cache" / "registry.json"
TTL = 24 * 3600


def online_enabled() -> bool:
    return os.getenv("AUDITBOT_ONLINE") == "1"


def _fetch(eco: str, name: str) -> dict:
    """{'exists': bool, 'created': iso|None} or {} when the registry couldn't be reached."""
    url = (f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json" if eco == "pypi"
           else f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}")
    req = urllib.request.Request(url, headers={"User-Agent": "audit-readiness-bot", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=4) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        return {"exists": False, "created": None} if e.code == 404 else {}
    except Exception:
        return {}
    if eco == "pypi":
        times = [f.get("upload_time_iso_8601") for files in data.get("releases", {}).values() for f in files]
        times = [t for t in times if t]
        return {"exists": True, "created": min(times) if times else None}
    return {"exists": True, "created": (data.get("time") or {}).get("created")}


def lookup(pairs: set[tuple[str, str]]) -> dict[tuple[str, str], dict]:
    try:
        cache = json.loads(CACHE.read_text(encoding="utf-8"))
    except Exception:
        cache = {}
    now, out, todo = time.time(), {}, []
    for eco, name in pairs:
        hit = cache.get(f"{eco}:{name}")
        if hit and now - hit.get("at", 0) < TTL:
            out[(eco, name)] = hit
        else:
            todo.append((eco, name))
    if todo:
        with ThreadPoolExecutor(max_workers=8) as pool:
            for (eco, name), res in zip(todo, pool.map(lambda p: _fetch(*p), todo)):
                if res:
                    res["at"] = now
                    cache[f"{eco}:{name}"] = out[(eco, name)] = res
        try:
            CACHE.parent.mkdir(parents=True, exist_ok=True)
            CACHE.write_text(json.dumps(cache), encoding="utf-8")
        except Exception:
            pass
    return out


def online_verdict(eco: str, name: str, info: dict) -> str | None:
    reg = "PyPI" if eco == "pypi" else "npm"
    if info.get("exists") is False:
        return (f"'{name}' does not exist on {reg}: most likely an AI-hallucinated dependency. Anyone can register "
                f"that name and ship code that runs at install time (slopsquatting).")
    created = info.get("created")
    if created:
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))).days
        except ValueError:
            return None
        if age < NEW_PACKAGE_DAYS:
            return (f"'{name}' was first published on {reg} {age} day{'s' if age != 1 else ''} ago: a brand-new "
                    f"package. Verify the publisher and source before installing.")
    return None
