#!/usr/bin/env python3
"""
INF 345 Milestone 3 - your image, built in CI and published to GHCR.

Due Sunday 25 October 2026, 23:59 Almaty time (UTC+5). Deadlines are judged by
commit time.

Where the evidence comes from:
  - your repository (a clone): Dockerfile, .dockerignore, workflows, history
  - ghcr.io, read ANONYMOUSLY - exactly what `docker pull` sees with no login
  - the GitHub API: the workflow run for the commit being marked
  - a Docker daemon, for the "it runs" block (skipped if there is none)

    python3 mark_m3.py --repo https://github.com/<you>/<project>
    python3 mark_m3.py --path .                  # your local checkout
    python3 mark_m3.py --path . --offline        # files only, no network
    python3 mark_m3.py --repo <url> --at-deadline

Three gates. Any gate failure scores the milestone 0.
Then 100 points in four blocks of 25. A block scores 25 only if every check
in it passes, and the report lists every problem at once.

Exit code 0 only if the score is 100. Nothing in this file is hidden from
students: it is the rubric.

Changed from the first draft of this marker (September), and why:
  - The registry is read over its HTTP API instead of relying on a local
    `docker pull`. That proves the package is PUBLIC (no credentials are sent)
    and needs no Docker daemon, so students without Docker Desktop still get
    feedback on the most important block.
  - The image checked is the one tagged with the SHA of the commit being
    marked. The first draft said "pull the SHA tag" but pulled `latest`.
  - `ARG` before `FROM` is legal Dockerfile and is accepted.
  - Week 5 told students "no compiler or build toolchain in the final image",
    so image hygiene now checks the final stage's base: golang, maven, gradle,
    rust, gcc, buildpack-deps, or a JDK (eclipse-temurin/openjdk/sapmachine/
    ibm-semeru-runtimes without "jre" in the tag) fails it. Full python/node
    images also carry gcc, but the 500 MB limit already catches those, so they
    are not counted twice.
  - `latest` is NOT required: only the tag equal to the marked commit's SHA
    (full, or 7+ characters, optionally "sha-" in front) counts.
"""

import argparse
import datetime
import fnmatch
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    import yaml
except ImportError:
    print("::error::pyyaml is required: pip install pyyaml")
    sys.exit(2)


DEADLINE = "2026-10-25T23:59:59+05:00"      # Sunday 25 Oct, 23:59 Almaty (UTC+5)
DEADLINE_UTC = (datetime.datetime.fromisoformat(DEADLINE)
                .astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
MAX_IMAGE_MB = 500                          # uncompressed, as `docker images` shows it
HEALTHZ_SECONDS = 30


# ================================================================ helpers

def run(cmd, cwd=None, timeout=120, env=None):
    """Run a command, never raise. Returns (rc, stdout, stderr)."""
    e = dict(os.environ)
    if env:
        e.update(env)
    try:
        # UTF-8 on every platform: a Windows laptop with a Russian or Kazakh locale
        # would otherwise decode `git log -p` with cp1251 and crash on the first
        # character it does not know.
        p = subprocess.run(cmd, cwd=cwd, env=e, timeout=timeout, capture_output=True,
                           encoding="utf-8", errors="replace")
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except OSError as exc:
        return 127, "", str(exc)


def free_port():
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def http_get(url, headers=None, timeout=20):
    """GET a URL. Never raises. Returns (status, headers, body_bytes).

    status is None when the server could not be reached at all.
    An Authorization header is never forwarded to a redirect target: ghcr.io
    redirects blob downloads to a storage host that must not see the token.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "inf345-mark-m3"})
    for k, v in (headers or {}).items():
        if k.lower() == "authorization":
            req.add_unredirected_header(k, v)
        else:
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            return r.status, hdrs, r.read()
    except urllib.error.HTTPError as exc:
        hdrs = {k.lower(): v for k, v in (exc.headers or {}).items()}
        try:
            body = exc.read()
        except Exception:
            body = b""
        return exc.code, hdrs, body
    except Exception as exc:
        return None, {}, str(exc).encode()


def read_text(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def repo_slug(url):
    m = re.search(r"github\.com[:/]+([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", url or "")
    return f"{m.group(1)}/{m.group(2)}" if m else None


def as_text(v):
    """Workflow values can be str, bool, int or missing. Compare them as text."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


# ====================================================== credentials (= M1)

# Same two tiers as M1, so a key is judged the same way in every milestone.
HIGH_CONFIDENCE = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"gh[pousr]_[A-Za-z0-9]{36,}", "GitHub token"),
    (r"github_pat_[A-Za-z0-9_]{50,}", "GitHub fine-grained token"),
    (r"-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----", "private key"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
]
DOC_VALUES = re.compile(r"(?i)(EXAMPLE|wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)")
FUZZY = [
    (r"(?i)\b(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*"
     r"['\"][^'\"\s]{12,}['\"]", "hardcoded credential"),
]
FUZZY_ALLOW = re.compile(
    r"(?i)(example|sample|placeholder|dummy|change[_-]?me|replace[_-]?me"
    r"|your[_\-\w]*|[_\-]here\b|xxx+|<[^>]+>|\$\{[^}]+\}|\bfake\b"
    r"|redacted|todo|test[_-]?token|secret[_-]?key[_-]?here)")


def scan_line(line):
    for pat, label in HIGH_CONFIDENCE:
        m = re.search(pat, line)
        if m and not DOC_VALUES.search(m.group(0)):
            return f"{label}: {m.group(0)[:40]}"
    for pat, label in FUZZY:
        m = re.search(pat, line)
        if m and not FUZZY_ALLOW.search(m.group(0)):
            return f"{label}: {m.group(0)[:60]}"
    return None


# ============================================================ Dockerfile

INSTR = re.compile(r"^\s*([A-Za-z]+)(?:\s+(.*))?$")
HEREDOC = re.compile(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?")


def parse_dockerfile(text):
    """-> (instructions, stages, global_args)

    instructions: [(INSTR, argument, stage_index)]  (stage -1 = before FROM)
    stages:       [{"image": str, "name": str or None}]
    global_args:  {NAME: default} declared before the first FROM
    Handles comments, backslash continuations and RUN <<EOF heredocs.
    """
    lines = text.splitlines()
    out, stages, gargs = [], [], {}
    stage, buf, i = -1, "", 0
    while i < len(lines):
        raw = lines[i].rstrip()
        i += 1
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        buf = (buf + " " + stripped) if buf else stripped
        if buf.endswith("\\"):
            buf = buf[:-1].rstrip()
            continue
        hd = HEREDOC.search(buf)
        if hd:                               # swallow the heredoc body
            delim, body = hd.group(1), []
            while i < len(lines) and lines[i].strip() != delim:
                body.append(lines[i].strip())
                i += 1
            i += 1
            buf = buf + " " + " ; ".join(body)
        m = INSTR.match(buf)
        buf = ""
        if not m:
            continue
        instr, arg = m.group(1).upper(), (m.group(2) or "").strip()
        if instr == "FROM":
            stage += 1
            words = [w for w in arg.split() if not w.startswith("--")]
            image = words[0] if words else ""
            name = words[2] if len(words) >= 3 and words[1].lower() == "as" else None
            stages.append({"image": image, "name": name})
        elif instr == "ARG" and stage == -1:
            k, _, v = arg.partition("=")
            gargs[k.strip()] = v.strip().strip("'\"") if _ else None
        out.append((instr, arg, stage))
    return out, stages, gargs


def resolve_args(image, gargs):
    """Substitute ${X}, $X and ${X:-d} from the ARGs declared before FROM."""
    def sub(m):
        name = m.group(1) or m.group(3)
        default = m.group(2)
        val = gargs.get(name)
        if val is None or val == "":
            return default if default is not None else m.group(0)
        return val
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)",
                  sub, image)


def image_tag(ref):
    """-> ('digest', d) | ('tag', t) | ('none', None) for an image reference."""
    if "@" in ref:
        return "digest", ref.split("@", 1)[1]
    last = ref.rsplit("/", 1)[-1]            # 'localhost:5000/x' - the port is not a tag
    if ":" in last:
        return "tag", last.split(":", 1)[1]
    return "none", None


DEP_INSTALL = re.compile(
    r"(pip3?\s+install[^;&|]*(-r\s|requirements)|poetry\s+install|pipenv\s+install|uv\s+sync"
    r"|npm\s+(ci|install)\b|yarn\s+install\b|yarn\s*(&&|;|$)|yarn\s+--(frozen-lockfile|immutable)"
    r"|pnpm\s+(i|install)\b"
    r"|go\s+mod\s+download|mvn[^;&|]*dependency:|gradle[^;&|]*dependencies"
    r"|bundle\s+install|composer\s+install|dotnet\s+restore|cargo\s+fetch)", re.I)

# COPY . .  /  COPY . /app  /  COPY ./ ./  /  ADD . .   - i.e. the whole build context
BROAD_COPY = re.compile(r"^(--\S+\s+)*\.\/?\s+\S+\s*$")


def effective_user(instrs, stages, gargs, idx, seen=None):
    """The USER the final image runs as: (value, where) or (None, why-not)."""
    seen = seen or set()
    if idx in seen:
        return None, "stage loop"
    seen.add(idx)
    users = [a for i, a, s in instrs if s == idx and i == "USER"]
    if users:
        return resolve_args(users[-1], gargs).strip(), "USER in the final stage"
    base = resolve_args(stages[idx]["image"], gargs)
    for j in range(idx):                      # FROM <an earlier stage>: inherit its USER
        if stages[j]["name"] and stages[j]["name"].lower() == base.lower():
            return effective_user(instrs, stages, gargs, j, seen)
    kind, tag = image_tag(base)
    if kind == "tag" and (tag == "nonroot" or tag.endswith("-nonroot")):
        return "nonroot", f"the base image '{base}' runs as nonroot"
    return None, "no USER in the final stage"


def is_root(user):
    u = user.split(":")[0].strip().strip("'\"")
    return u in ("root", "0")


# Images that ARE a build toolchain (week 5: "no compiler in the final image").
TOOLCHAIN_IMAGES = {"golang", "maven", "gradle", "rust", "gcc", "buildpack-deps"}
JDK_IMAGES = {"eclipse-temurin", "openjdk", "sapmachine", "ibm-semeru-runtimes"}


def final_base(stages, gargs, idx, seen=None):
    """The real image a stage starts from, following  FROM <an earlier stage>."""
    seen = seen or set()
    if idx in seen:
        return None
    seen.add(idx)
    base = resolve_args(stages[idx]["image"], gargs)
    for j in range(idx):
        if stages[j]["name"] and stages[j]["name"].lower() == base.lower():
            return final_base(stages, gargs, j, seen)
    return base


def toolchain_problem(ref):
    """A problem string if `ref` is a compiler/build-tool image, else None."""
    if not ref or "$" in ref:
        return None
    last = ref.split("@")[0].rsplit("/", 1)[-1]
    repo, _, tag = last.partition(":")
    repo, tag = repo.lower(), tag.lower()
    if repo in TOOLCHAIN_IMAGES:
        return (f"the final stage is FROM {ref}: the whole {repo} toolchain ships with your "
                f"app. Build in a first stage and COPY --from it into a small runtime "
                f"image (week 5, multi-stage)")
    if repo in JDK_IMAGES and "jre" not in tag:
        return (f"the final stage is FROM {ref}: a JDK, compiler included. Compile in a "
                f"first stage and run on the -jre image (week 5)")
    return None


# ========================================================== .dockerignore

def dockerignore_excludes(text, name):
    """Does .dockerignore keep `name` (at the context root) out of the build?

    Rules are applied in order and the last match wins; '!' re-includes.
    """
    excluded = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        neg = line.startswith("!")
        pat = line[1:].strip() if neg else line
        if pat.startswith("./"):
            pat = pat[2:]
        pat = pat.lstrip("/").rstrip("/")
        cands = [pat]
        while cands[-1].startswith("**/"):
            cands.append(cands[-1][3:])
        if pat in ("**", "*") or any(fnmatch.fnmatchcase(name, c) for c in cands):
            excluded = not neg
    return excluded


# ============================================================= workflows

def load_workflows(path):
    d = os.path.join(path, ".github", "workflows")
    out = []
    if not os.path.isdir(d):
        return out
    for name in sorted(os.listdir(d)):
        if not name.endswith((".yml", ".yaml")):
            continue
        raw = read_text(os.path.join(d, name))
        try:
            wf = yaml.safe_load(raw)
            out.append((name, wf if isinstance(wf, dict) else None, raw))
        except yaml.YAMLError:
            out.append((name, None, raw))
    return out


def triggers_of(wf):
    on = wf.get("on", wf.get(True))            # YAML 1.1 reads a bare `on:` as True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    if isinstance(on, dict):
        return set(on.keys())
    return set()


def jobs_of(wf):
    jobs = wf.get("jobs") if isinstance(wf, dict) else None
    return [(k, v) for k, v in (jobs or {}).items() if isinstance(v, dict)]


def steps_of(job):
    return [s for s in (job.get("steps") or []) if isinstance(s, dict)]


def uses_of(step):
    u = step.get("uses")
    return u.strip() if isinstance(u, str) else ""


def with_env(text, *scopes):
    """Replace ${{ env.NAME }} using the step, job and workflow `env:` maps -
    GitHub's own example writes  registry: ${{ env.REGISTRY }}."""
    def sub(m):
        for sc in scopes:
            env = (sc or {}).get("env") if isinstance(sc, dict) else None
            if isinstance(env, dict) and m.group(1) in env:
                return as_text(env[m.group(1)])
        return m.group(0)
    return re.sub(r"\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}", sub, as_text(text))


def action_is(step, name):
    return uses_of(step).lower().split("@")[0] == name


PUSH_RUN = re.compile(r"docker\s+(image\s+)?push\b|buildx\s+build[^\n]*--push|"
                      r"docker\s+build[^\n]*--push")


def push_step_index(job):
    """Index of the first step that pushes an image, or None."""
    for n, s in enumerate(steps_of(job)):
        if action_is(s, "docker/build-push-action"):
            p = as_text((s.get("with") or {}).get("push")).strip().lower()
            if p and p != "false":
                return n
        if PUSH_RUN.search(as_text(s.get("run"))):
            return n
    return None


def publishing_jobs(wfs):
    """[(file, wf, job_id, job, push_index)] for every job that pushes to ghcr.io."""
    found = []
    for name, wf, raw in wfs:
        if not wf or "ghcr.io" not in raw:
            continue
        for jid, job in jobs_of(wf):
            idx = push_step_index(job)
            if idx is not None:
                found.append((name, wf, jid, job, idx))
    return found


def needs_of(job):
    n = job.get("needs")
    if isinstance(n, str):
        return {n}
    if isinstance(n, list):
        return {x for x in n if isinstance(x, str)}
    return set()


def needs_closure(wf, jid):
    jobs = dict(jobs_of(wf))
    todo, seen = list(needs_of(jobs.get(jid, {}))), set()
    while todo:
        j = todo.pop()
        if j in seen:
            continue
        seen.add(j)
        todo.extend(needs_of(jobs.get(j, {})))
    return seen


# ============================================================== evidence

MANIFEST_ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


def sha_tags(tags, sha):
    """Tags that name this commit: the full SHA or a 7+ prefix, optional 'sha-'."""
    out = []
    for t in tags:
        core = t[4:] if t.startswith("sha-") else t
        if len(core) >= 7 and re.fullmatch(r"[0-9a-f]+", core) and sha.startswith(core):
            out.append(t)
    return sorted(out, key=lambda t: -len(t))       # longest (full SHA) first


def read_registry(image, sha, get=http_get):
    """Read ghcr.io the way an anonymous `docker pull` would.

    1. ask for an anonymous pull token (a private package gets none)
    2. ask for the manifest of the tags that name this commit - the same
       request `docker pull <image>:<tag>` makes
    3. only if none of those exist, list the tags, to say what IS there
    Returns {"reachable", "public", "tags", "tag", "digest", "detail"}.
    """
    ev = {"reachable": False, "public": False, "tags": [], "tag": None,
          "digest": None, "detail": ""}
    host, _, name = image.partition("/")
    q = urllib.parse.urlencode({"scope": f"repository:{name}:pull", "service": host})
    status, _, body = get(f"https://{host}/token?{q}")
    if status is None:
        ev["detail"] = f"could not reach {host}: {body.decode(errors='replace')[:120]}"
        return ev
    ev["reachable"] = True
    if status != 200:
        ev["detail"] = f"{host} gives no anonymous access to {name} (HTTP {status})"
        return ev
    try:
        token = json.loads(body).get("token", "")
    except ValueError:
        token = ""
    auth = {"Authorization": f"Bearer {token}"} if token else {}

    def manifest(tag):
        st, hdrs, raw = get(f"https://{host}/v2/{name}/manifests/{tag}",
                            dict(auth, Accept=MANIFEST_ACCEPT))
        if st in (401, 403):
            return "denied", None, None
        if st != 200:
            return "missing", None, None
        try:
            man = json.loads(raw)
        except ValueError:
            man = {}
        return "ok", hdrs.get("docker-content-digest"), man

    found = None
    for tag in (sha, f"sha-{sha}", f"sha-{sha[:7]}", sha[:7]):
        verdict, digest, man = manifest(tag)
        if verdict == "denied":
            ev["detail"] = f"{host} refused to show {image} to an anonymous caller"
            return ev
        if verdict == "ok":
            found = (tag, digest, man)
            break

    if not found:                                  # say what is there instead
        tags, url, pages = [], f"https://{host}/v2/{name}/tags/list", 0
        while url and pages < 20:
            pages += 1
            st, hdrs, raw = get(url, auth)
            if st in (401, 403):
                ev["detail"] = f"{host} refused to list the tags of {image}"
                return ev
            if st != 200:
                ev["public"] = True
                ev["detail"] = (f"listing tags returned HTTP {st}"
                                + (" - nothing pushed under this name?" if st == 404 else ""))
                return ev
            try:
                tags.extend(json.loads(raw).get("tags") or [])
            except ValueError:
                break
            nxt = re.search(r'<([^>]+)>\s*;\s*rel="?next"?', hdrs.get("link", ""))
            url = urllib.parse.urljoin(f"https://{host}", nxt.group(1)) if nxt else None
        ev["public"], ev["tags"] = True, tags
        for tag in sha_tags(tags, sha):             # e.g. a 12-character short SHA
            verdict, digest, man = manifest(tag)
            if verdict == "ok":
                found = (tag, digest, man)
                break
        if not found:
            return ev

    ev["public"] = True
    ev["tag"], ev["digest"], man = found
    plats = [(m.get("platform") or {}) for m in (man or {}).get("manifests", [])]
    if plats and not any(p.get("os") == "linux" and p.get("architecture") == "amd64"
                         for p in plats):
        ev["detail"] = "the image has no linux/amd64 variant, so no ordinary server can run it"
    return ev


def fetch_runs(slug, sha=None):
    """Workflow runs - for one commit, or the newest 100 of the repository.
    Returns (runs or None, note)."""
    path = f"repos/{slug}/actions/runs?per_page=100" + (f"&head_sha={sha}" if sha else "")
    if shutil.which("gh"):
        rc, out, err = run(["gh", "api", "-X", "GET", path], timeout=60)
        if rc == 0:
            try:
                return json.loads(out).get("workflow_runs", []), "gh api"
            except ValueError:
                pass
        note = f"gh api failed: {(err or out).strip()[:100]}"
    else:
        note = "gh not installed"
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    status, _, body = http_get(f"https://api.github.com/{path}", headers, timeout=30)
    if status == 200:
        try:
            return json.loads(body).get("workflow_runs", []), "the GitHub API"
        except ValueError:
            return None, f"{note}; the API answer was not JSON"
    if status in (403, 429):
        return None, f"{note}; API rate limit - set GH_TOKEN (or GITHUB_TOKEN) or install gh"
    return None, f"{note}; API returned {status}"


class Docker:
    """The four docker commands block 4 needs. Replaced by a fake in the tests.

    The image is always pulled and run as linux/amd64, the platform of GitHub's
    runners and of the official marking. On an Apple Silicon Mac a plain pull
    asks for linux/arm64 and fails with "no matching manifest"; with --platform,
    Docker Desktop runs the amd64 image through emulation instead.
    """

    PLATFORM = "linux/amd64"

    def available(self):
        return run(["docker", "info"], timeout=25)[0] == 0

    def pull(self, ref):
        rc, _, err = run(["docker", "pull", "--quiet", "--platform", self.PLATFORM, ref],
                         timeout=420)
        return rc == 0, err.strip()

    def size(self, ref):
        rc, out, _ = run(["docker", "image", "inspect", "--format", "{{.Size}}", ref], timeout=30)
        try:
            return int(out.strip()) if rc == 0 else None
        except ValueError:
            return None

    def start(self, ref, port):
        rc, out, err = run(["docker", "run", "-d", "--rm", "--platform", self.PLATFORM,
                            "-e", f"PORT={port}", "-p", f"{port}:{port}", ref], timeout=90)
        return (rc == 0), (out.strip() if rc == 0 else err.strip())

    def logs(self, cid):
        return run(["docker", "logs", "--tail", "20", cid], timeout=20)[1:]

    def kill(self, cid):
        run(["docker", "kill", cid], timeout=30)


# ================================================================= gates

def gate_dockerfile(ctx):
    if ctx["dockerfile"] is None:
        return False, "no Dockerfile at the repository root"
    if not ctx["stages"]:
        return False, "the Dockerfile has no FROM line I could parse"
    return True, (f"Dockerfile: {len(ctx['instrs'])} instructions, "
                  f"{len(ctx['stages'])} stage(s)")


def gate_no_secrets(ctx):
    if not os.path.isdir(os.path.join(ctx["path"], ".git")):
        return False, "not a git repository, so the history cannot be checked"
    rc, out, _ = run(["git", "log", "-p", "--all", "--no-color"], cwd=ctx["path"], timeout=180)
    if rc != 0:
        return False, "could not read the git history"
    hits = [h for h in (scan_line(l) for l in out.splitlines() if l.startswith("+")) if h]
    if hits:
        return False, "credential found in git history - " + "; ".join(sorted(set(hits))[:3])
    for instr, arg, _ in ctx["instrs"]:
        if instr in ("ENV", "ARG") and re.search(
                r"(?i)(password|secret|token|api[_-]?key)\w*\s*[= ]\s*\S{12,}", arg):
            if not re.search(r"(?i)(example|changeme|your[_-]|placeholder|\$\{|\$[A-Z_])", arg):
                return False, f"a credential baked into the image: {instr} {arg[:48]}"
    return True, "no credentials in the history, and none in ENV or ARG"


def gate_publishes(ctx):
    if not ctx["workflows"]:
        return False, "no workflow files under .github/workflows/"
    broken = [n for n, wf, _ in ctx["workflows"] if wf is None]
    if broken:
        return False, f"{broken[0]} is not valid YAML"
    if not ctx["publishers"]:
        return False, ("no workflow job pushes an image to ghcr.io. M3 is an image "
                       "that CI builds and publishes - not one you push from your laptop.")
    f, _, jid, _, _ = ctx["publishers"][0]
    return True, f"job '{jid}' in {f} pushes to ghcr.io"


# ================================================================ blocks

def block_published(ctx):
    """The image for the marked commit is in GHCR, public, and CI built it."""
    if ctx["offline"]:
        return None, "skipped (--offline): needs ghcr.io and the GitHub API"
    ev = ctx["registry"]
    if not ev["reachable"]:
        return None, f"skipped: {ev['detail']}"
    img, sha = ctx["image"], ctx["sha"]
    if not ev["public"]:
        return 0, (f"{img} is not publicly pullable ({ev['detail']}). New packages always "
                   f"start PRIVATE. Open the package on GitHub -> Package settings -> "
                   f"Danger Zone -> Change visibility -> Public. If you did that, check "
                   f"the image name: it must be exactly {img}, in lowercase.")
    if not ev["tag"]:
        shown = ", ".join(ev["tags"][:6]) or "none"
        extra = f" {ev['detail']}." if ev["detail"] else ""
        return 0, (f"{img} is public, but no tag names commit {sha[:7]} (the commit being "
                   f"marked). Tags found: {shown}.{extra} Did the pipeline run - and "
                   f"reach its push step - for this commit?")
    if ev["detail"]:
        return 0, ev["detail"]
    note = f"{img}:{ev['tag'][:19]} -> {ev['digest'] or 'digest unknown'}"
    runs, why = ctx["runs"], ctx["runs_note"]
    if runs is None:
        ctx["notes"].append(f"run history not checked ({why})")
        return 25, note + " (run history not checked)"
    wanted = {f".github/workflows/{f}" for f, *_ in ctx["publishers"]}
    mine = [r for r in runs if r.get("head_sha") == sha]
    pub = [r for r in mine if r.get("path", "").split("@")[0] in wanted] or mine
    if not pub:
        return 0, f"no workflow run found for commit {sha[:7]} - the image was not built by CI"
    latest = sorted(pub, key=lambda r: r.get("run_started_at") or "", reverse=True)[0]
    if latest.get("status") != "completed":
        return 0, f"the run for {sha[:7]} has not finished yet ({latest.get('html_url', '')})"
    if latest.get("conclusion") != "success":
        return 0, (f"the run that should have published {sha[:7]} concluded "
                   f"'{latest.get('conclusion')}': {latest.get('html_url', '')}")
    ctx["run_started_at"] = latest.get("run_started_at")
    return 25, note + ", built by a green run"


def block_pipeline(ctx):
    """How the image gets published: least privilege, gated, scanned, pinned."""
    problems = []
    fname, wf, jid, job, push_i = ctx["publishers"][0]
    steps = steps_of(job)

    # 1. the token can write packages, and nothing asks for everything
    raws = "\n".join(r for _, _, r in ctx["workflows"])
    if re.search(r"(?m)^\s*permissions\s*:\s*write-all\b", raws):
        problems.append("'permissions: write-all' hands the token every permission - "
                        "grant packages: write and nothing it does not need")
    perms = job.get("permissions", wf.get("permissions"))
    if perms is None:
        problems.append(f"job '{jid}' has no permissions: block - say what the token may "
                        f"do (contents: read, packages: write)")
    elif not (isinstance(perms, dict) and as_text(perms.get("packages")) == "write"):
        problems.append(f"job '{jid}' does not grant packages: write")

    # 2. it logs in with the run's own short-lived token, not a personal one
    logins, bad = 0, None
    for s in steps:
        w = s.get("with") or {}
        text = ""
        registry = with_env(w.get("registry"), s, job, wf)
        if action_is(s, "docker/login-action") and "ghcr.io" in registry:
            text = with_env(w.get("password"), s, job, wf)
        elif re.search(r"docker\s+login\b[^\n]*ghcr\.io", as_text(s.get("run"))):
            text = as_text(s.get("run")) + " " + json.dumps(s.get("env") or {})
        else:
            continue
        logins += 1
        if not re.search(r"(?i)secrets\.GITHUB_TOKEN|github\.token", text):
            bad = re.search(r"secrets\.\w+", text)
    if logins == 0:
        problems.append(f"job '{jid}' never logs in to ghcr.io")
    elif bad:
        problems.append(f"logs in to ghcr.io with {bad.group(0)} - use secrets.GITHUB_TOKEN: "
                        f"it is created for the run and expires with it")

    # 3. a pull request never publishes
    if triggers_of(wf) & {"pull_request", "pull_request_target"}:
        guard = re.compile(r"github\.event_name|github\.ref|refs/(heads|tags)/")
        texts = [as_text(job.get("if")), as_text(steps[push_i].get("if")),
                 as_text((steps[push_i].get("with") or {}).get("push"))]
        if not any(guard.search(t) for t in texts):
            problems.append(f"{fname} runs on pull_request and job '{jid}' would push from a "
                            f"pull request too - add  if: github.event_name == 'push'")

    # 4. publishing waits for the tests
    wf_jobs = dict(jobs_of(wf))
    testers = {j for j, jb in wf_jobs.items()
               if any("scripts/test.sh" in as_text(s.get("run")) for s in steps_of(jb))}
    tested_here = any("scripts/test.sh" in as_text(s.get("run")) for s in steps[:push_i])
    if not tested_here and not (needs_closure(wf, jid) & testers):
        problems.append(f"nothing makes job '{jid}' wait for your tests - add  needs: "
                        f"<the job that runs scripts/test.sh>")

    # 5. the image is scanned before it is pushed, and the scan can fail the build
    scan = scan_before_push(wf, jid, steps, push_i)
    if scan:
        problems.append(scan)

    # 6. third-party actions pinned to a commit, nothing on a branch
    problems.extend(pin_problems(ctx["workflows"]))

    if problems:
        return 0, "; ".join(problems)
    return 25, (f"job '{jid}': packages: write, GITHUB_TOKEN, not on pull requests, "
                f"waits for tests, scans before pushing, actions pinned")


def scanner_verdict(step):
    """None if this step is not an image scan; else '' (fine) or a problem."""
    w = step.get("with") or {}
    runs = as_text(step.get("run"))
    if action_is(step, "aquasecurity/trivy-action"):
        if as_text(w.get("scan-type") or "image").lower() != "image":
            return "the Trivy step scans the source, not the image (scan-type)"
        if as_text(w.get("exit-code")).strip() in ("", "0"):
            return ("the Trivy step can never fail the build - set  exit-code: \"1\"  "
                    "(a scan nobody has to act on is a report nobody reads)")
        return ""
    if re.search(r"\btrivy\s+(image|i)\b", runs):
        return "" if re.search(r"--exit-code[ =]+[1-9]", runs) else \
            "'trivy image' runs without --exit-code 1, so it can never fail the build"
    if action_is(step, "anchore/scan-action"):
        return "" if as_text(w.get("fail-build")).lower() != "false" else \
            "the Grype step has fail-build: false"
    if re.search(r"\bgrype\b", runs):
        return "" if "--fail-on" in runs else "grype runs without --fail-on"
    if action_is(step, "docker/scout-action") or re.search(r"docker\s+scout\s+cves", runs):
        ok = as_text(w.get("exit-code")).lower() == "true" or "--exit-code" in runs
        return "" if ok else "Docker Scout runs without exit-code, so it cannot fail the build"
    return None


def scan_before_push(wf, jid, steps, push_i):
    verdicts = [v for v in (scanner_verdict(s) for s in steps[:push_i]) if v is not None]
    script = as_text(steps[push_i].get("run"))       # one run: step that scans, then pushes
    m = PUSH_RUN.search(script)
    if m:
        v = scanner_verdict({"run": script[:m.start()]})
        if v is not None:
            verdicts.append(v)
    wf_jobs = dict(jobs_of(wf))
    for j in needs_closure(wf, jid):
        verdicts += [v for v in (scanner_verdict(s) for s in steps_of(wf_jobs.get(j, {})))
                     if v is not None]
    if "" in verdicts:
        return None
    if verdicts:
        return verdicts[0]
    late = [v for v in (scanner_verdict(s) for s in steps[push_i + 1:]) if v is not None]
    if late:
        return "the image is scanned AFTER it is pushed - scan first, push only if it is clean"
    return ("no vulnerability scan before the push - add the Trivy step "
            "(aquasecurity/trivy-action, exit-code: \"1\")")


FIRST_PARTY = ("actions", "github")


def pin_problems(wfs):
    problems = []
    for fname, wf, _ in wfs:
        if not wf:
            continue
        refs = []
        for jid, job in jobs_of(wf):
            if isinstance(job.get("uses"), str):
                refs.append(job["uses"].strip())          # a reusable workflow
            refs.extend(uses_of(s) for s in steps_of(job) if uses_of(s))
        for u in refs:
            if u.startswith(("./", "docker://")):
                continue
            repo, _, ref = u.partition("@")
            owner = repo.split("/")[0].lower()
            if not ref:
                problems.append(f"{u} has no version at all")
            elif ref in ("main", "master", "HEAD", "latest") or ref.startswith("refs/heads/"):
                problems.append(f"{u} follows a branch - it changes whenever they push")
            elif owner not in FIRST_PARTY and not re.fullmatch(r"[0-9a-f]{40}", ref):
                problems.append(f"{u} is a third-party action on a tag, and tags can be "
                                f"moved (Trivy, March 2026) - pin it to the full 40-character "
                                f"commit SHA and keep the version in a comment")
    seen, out = set(), []
    for p in problems:                           # one line per action, not per use
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def block_hygiene(ctx):
    """What is inside the image, read from the Dockerfile."""
    problems = []
    instrs, stages, gargs = ctx["instrs"], ctx["stages"], ctx["gargs"]
    last = len(stages) - 1

    user, where = effective_user(instrs, stages, gargs, last)
    if user is None:
        problems.append(f"{where} - the container runs as root. Add  USER 1000  "
                        f"(or any non-root user) after the last FROM")
    elif is_root(user):
        problems.append(f"USER {user} is root")

    tool = toolchain_problem(final_base(stages, gargs, last))
    if tool:
        problems.append(tool)

    names = {s["name"].lower() for s in stages if s["name"]}
    for n, st in enumerate(stages):
        ref = resolve_args(st["image"], gargs)
        if ref.lower() == "scratch" or ref.lower() in names:
            continue
        if "$" in ref:
            ctx["notes"].append(f"FROM {st['image']}: could not resolve the variable")
            continue
        kind, tag = image_tag(ref)
        if kind == "none":
            problems.append(f"FROM {ref} has no tag, so it means {ref}:latest - "
                            f"name a version, e.g. python:3.13-slim")
        elif kind == "tag" and tag == "latest":
            problems.append(f"FROM {ref} - latest is not a version; name one")

    if ctx["dockerignore"] is None:
        problems.append("no .dockerignore - your .git and any .env go into the build context")
    else:
        for must in (".git", ".env"):
            if not dockerignore_excludes(ctx["dockerignore"], must):
                problems.append(f".dockerignore does not exclude {must}")

    for s in range(len(stages)):
        items = [(i, a) for i, a, st in instrs if st == s]
        install = next((k for k, (i, a) in enumerate(items)
                        if i == "RUN" and DEP_INSTALL.search(a)), None)
        broad = next((k for k, (i, a) in enumerate(items)
                      if i in ("COPY", "ADD") and BROAD_COPY.match(a)), None)
        if install is not None and broad is not None and broad < install:
            problems.append(f"stage {s + 1}: COPY . comes before the dependency install, so "
                            f"every source edit reinstalls everything (week 5)")
            break

    if problems:
        return 0, "; ".join(problems)
    return 25, (f"runs as {user} ({where}); bases pinned; no toolchain in the final stage; "
                f".dockerignore; layers ordered")


def block_runs(ctx):
    """Pull the image for this commit and run it with a random PORT."""
    dk = ctx["docker"]
    if dk is None:
        return None, "skipped: needs a Docker daemon (none reachable, or --offline)"
    tag = (ctx["registry"] or {}).get("tag") or ctx["sha"]
    ref = f"{ctx['image']}:{tag}"
    ok, err = dk.pull(ref)
    if not ok:
        if re.search(r"no matching manifest", err, re.I):
            hint = " The image has no linux/amd64 variant."
        elif re.search(r"denied|unauthorized|not found", err, re.I):
            hint = " Is the package public?"
        else:
            hint = ""
        return 0, f"could not pull {ref}.{hint} {err[:160]}"
    size = dk.size(ref)
    if size is not None and size > MAX_IMAGE_MB * 1000 * 1000:
        return 0, (f"the image is {size / 1e6:.0f} MB, over the {MAX_IMAGE_MB} MB limit - "
                   f"use a -slim base, or a second stage that leaves the toolchain behind")
    port = free_port()
    ok, cid = dk.start(ref, port)
    if not ok:
        return 0, f"the container would not start: {cid[:200]}"
    try:
        deadline = time.time() + HEALTHZ_SECONDS
        while time.time() < deadline:
            status, _, _ = http_get(f"http://127.0.0.1:{port}/healthz", timeout=2)
            if status == 200:
                mb = f"{size / 1e6:.0f} MB, " if size else ""
                return 25, f"pulled {ref[:60]}, {mb}/healthz 200 on PORT={port}"
            time.sleep(1)
        out, err = dk.logs(cid)
        return 0, (f"/healthz did not answer 200 within {HEALTHZ_SECONDS}s on PORT={port} "
                   f"(listening on 0.0.0.0? reading $PORT?). Last logs: "
                   f"{(out + err).strip()[-220:]}")
    finally:
        dk.kill(cid)


GATES = [("dockerfile", gate_dockerfile),
         ("no credentials", gate_no_secrets),
         ("CI publishes", gate_publishes)]
BLOCKS = [("published", block_published),
          ("pipeline", block_pipeline),
          ("image hygiene", block_hygiene),
          ("it runs", block_runs)]


# ================================================================ report

def tree_at(path, rev):
    """Extract the files of commit `rev` into a new temporary folder (or None)."""
    tmp = tempfile.mkdtemp(prefix="m3-tree-")
    try:
        arc = subprocess.run(["git", "archive", "--format=tar", rev], cwd=path,
                             capture_output=True, timeout=180)
        if arc.returncode == 0:
            ext = subprocess.run(["tar", "-x", "-C", tmp], input=arc.stdout,
                                 capture_output=True, timeout=180)
            if ext.returncode == 0:
                return tmp
    except (OSError, subprocess.SubprocessError):
        pass
    shutil.rmtree(tmp, ignore_errors=True)
    return None


def build_ctx(path, slug, image=None, at_deadline=False, offline=False,
              registry_get=None, runs=None, runs_note="", docker=None):
    head, notes = "HEAD", []
    if at_deadline:
        rc, out, _ = run(["git", "rev-list", "-1", "--first-parent",
                          f"--before={DEADLINE}", "HEAD"], cwd=path)
        if rc == 0 and out.strip():
            head = out.strip()
            notes.append(f"marking the last commit on or before {DEADLINE}")
        else:
            notes.append(f"no commit on or before {DEADLINE} - marking HEAD instead")
    rc, out, _ = run(["git", "log", "-1", "--format=%H%x09%cI%x09%s", head], cwd=path)
    sha, date, subject = (out.strip().split("\t") + ["", "", ""])[:3] if rc == 0 else ("", "", "")

    # With --at-deadline the files must come from the deadline commit, not from the
    # newest commit on disk: a push after the deadline must not change the mark.
    # The commit is extracted into a temporary folder, so a student's working tree
    # is never touched. History checks (credentials) still use the repository.
    files_root, tree_tmp = path, None
    if at_deadline and head != "HEAD" and sha:
        rc2, out2, _ = run(["git", "rev-parse", "HEAD"], cwd=path)
        if not (rc2 == 0 and out2.strip() == sha):
            tree_tmp = tree_at(path, sha)
            if tree_tmp:
                files_root = tree_tmp
            else:
                notes.append("could not extract the deadline commit - reading the newest files")
    try:
        df = None
        for n in ("Dockerfile", "dockerfile"):
            p = os.path.join(files_root, n)
            if os.path.isfile(p):
                df = read_text(p)
                break
        instrs, stages, gargs = parse_dockerfile(df or "")
        di_path = os.path.join(files_root, ".dockerignore")
        dockerignore = read_text(di_path) if os.path.isfile(di_path) else None
        wfs = load_workflows(files_root)
    finally:
        if tree_tmp:
            shutil.rmtree(tree_tmp, ignore_errors=True)
    image = (image or f"ghcr.io/{slug}").lower() if (image or slug) else None
    ctx = {"path": path, "slug": slug, "image": image, "sha": sha, "date": date,
           "subject": subject, "dockerfile": df, "instrs": instrs, "stages": stages,
           "gargs": gargs, "workflows": wfs, "publishers": publishing_jobs(wfs),
           "dockerignore": dockerignore,
           "offline": offline, "registry": None, "runs": runs, "runs_note": runs_note,
           "docker": docker, "notes": notes, "run_started_at": None}
    if not offline and image and sha:
        ctx["registry"] = read_registry(image, sha, registry_get or http_get)
        if runs is None and slug and not runs_note:
            ctx["runs"], ctx["runs_note"] = fetch_runs(slug, sha)
    return ctx


def mark(ctx, as_json=False):
    rep = {"repo": ctx["slug"], "image": ctx["image"],
           "commit": {"sha": ctx["sha"], "date": ctx["date"], "subject": ctx["subject"]},
           "gates": [], "blocks": [], "skipped": [], "score": 0, "capped": False,
           "notes": ctx["notes"]}
    for name, fn in GATES:
        ok, detail = fn(ctx)
        rep["gates"].append({"name": name, "ok": ok, "detail": detail})
        rep["capped"] = rep["capped"] or not ok
    if not rep["capped"]:
        for name, fn in BLOCKS:
            pts, detail = fn(ctx)
            if pts is None:
                rep["skipped"].append({"name": name, "detail": detail})
                continue
            rep["blocks"].append({"name": name, "points": pts, "detail": detail})
            rep["score"] += pts
    started = ctx.get("run_started_at")
    if started and started > DEADLINE_UTC:
        rep["notes"].append(f"the pipeline for this commit started at {started}, "
                            f"after the deadline ({DEADLINE_UTC})")
    rep["checked_out_of"] = 25 * len(rep["blocks"]) if not rep["capped"] else 100
    code = 0 if rep["score"] == 100 else 1
    if as_json:
        print(json.dumps(rep, indent=2))
        return code

    print(f"\n  M3 for {ctx['slug'] or ctx['path']}")
    if ctx["sha"]:
        print(f"  commit {ctx['sha'][:7]}  {ctx['date']}  {ctx['subject'][:50]}")
    if ctx["image"]:
        print(f"  image  {ctx['image']}")
    print()
    for g in rep["gates"]:
        print(f"  [gate {'ok ' if g['ok'] else 'FAIL'}] {g['name']}: {g['detail']}")
    if rep["capped"]:
        print("\n  A gate failed, so this milestone scores 0.\n\nSCORE: 0/100")
        return 1
    print()
    results = {b["name"]: b for b in rep["blocks"] + rep["skipped"]}
    for name, _ in BLOCKS:                      # in rubric order, skipped ones included
        b = results[name]
        pts = f"{b['points']:>2}" if "points" in b else "--"
        print(f"  [ {pts}/25 ] {name}")
        print(f"            {b['detail']}")
    for n in rep["notes"]:
        print(f"  note: {n}")
    if rep["skipped"]:
        print(f"\nSCORE: {rep['score']}/{rep['checked_out_of']} checked "
              f"({len(rep['skipped'])} block(s) not checked - the real mark checks all four)")
    else:
        print(f"\nSCORE: {rep['score']}/100")
    return code


def main(argv=None):
    ap = argparse.ArgumentParser(description="Mark INF 345 milestone 3.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--repo", help="https://github.com/<user>/<project> - cloned fresh")
    src.add_argument("--path", help="a local checkout (marks its HEAD)")
    ap.add_argument("--image", help="override: ghcr.io/<owner>/<name>")
    ap.add_argument("--at-deadline", action="store_true",
                    help=f"mark the last commit on or before {DEADLINE}")
    ap.add_argument("--offline", action="store_true",
                    help="files only: no registry, no API, no Docker")
    ap.add_argument("--no-docker", action="store_true", help="skip the 'it runs' block")
    ap.add_argument("--runs-json", help="read workflow runs from a file saved by --fetch-runs")
    ap.add_argument("--fetch-runs", metavar="OWNER/REPO",
                    help="print the repository's newest 100 workflow runs as JSON and stop "
                         "(the marking workflow does this in a step that has a token, so the "
                         "step that runs student images never needs one)")
    ap.add_argument("--json", action="store_true")
    if argv is None:
        argv = sys.argv[1:]
    if "--fetch-runs" in argv:                       # a mode of its own: no marking
        i = argv.index("--fetch-runs")
        slug = argv[i + 1] if i + 1 < len(argv) else ""
        slug = repo_slug(slug) or slug
        runs, note = fetch_runs(slug)
        if runs is None:                             # "unknown" - never "no runs"
            print(f"::warning::could not read runs for {slug}: {note}", file=sys.stderr)
        print(json.dumps(runs))
        return 0 if runs is not None else 1
    a = ap.parse_args(argv)

    slug = repo_slug(a.repo) if a.repo else None
    if a.path and not slug:
        rc, out, _ = run(["git", "remote", "get-url", "origin"], cwd=a.path)
        slug = repo_slug(out.strip()) if rc == 0 else None
    if not slug and not a.image and not a.offline:
        print("::error::cannot work out <owner>/<repo> - pass --repo, or --image")
        return 2

    runs, note = None, ""
    if a.runs_json:
        runs = json.loads(read_text(a.runs_json))
        note = "a saved file" if runs is not None else "could not be read when it was fetched"
    docker = None
    if not (a.offline or a.no_docker):
        d = Docker()
        docker = d if d.available() else None
        if docker is None:
            print("::warning::no Docker daemon reachable - the 'it runs' block is skipped")

    def go(path):
        ctx = build_ctx(path, slug, a.image, a.at_deadline, a.offline,
                        runs=runs, runs_note=note, docker=docker)
        return mark(ctx, a.json)

    if a.path:
        return go(os.path.abspath(a.path))
    tmp = tempfile.mkdtemp(prefix="m3-")
    try:
        rc, _, err = run(["git", "clone", "--quiet", a.repo, tmp], timeout=300)
        if rc != 0:
            print(f"::error::could not clone {a.repo}: {err.strip()[:200]}")
            return 1
        return go(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
