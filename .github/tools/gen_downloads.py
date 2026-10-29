"""Generates the docs "Downloads" page from the repository's GitHub Releases.

Run by mkdocs through the gen-files plugin (see mkdocs.yml). Every release
body is built by release-notes.sh: its ChangeLog section, the contributors,
then the assets grouped by kind. This page shows each release's assets first
and its changelog below them, newest release first.

GITHUB_TOKEN, when set, only raises the API rate limit.
"""

import json
import os
import re
import sys
import urllib.request

import mkdocs_gen_files

REPO = "rawstor/librawstor"
API = f"https://api.github.com/repos/{REPO}/releases?per_page=100"


def fetch_releases():
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    releases = []
    url = API
    while url:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=30) as response:
            releases += json.load(response)
            link = response.headers.get("Link", "")
        match = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = match.group(1) if match else None
    return [r for r in releases if not r["draft"]]


def sections(body):
    """Splits a release body into {"## heading": text}, in order."""
    ret = {}
    heading = None
    for line in body.splitlines():
        if line.startswith("## "):
            heading = line
            ret[heading] = []
        elif heading is not None:
            ret[heading].append(line)
    return {h: "\n".join(lines).strip() for h, lines in ret.items()}


def demote(text):
    return re.sub(r"^(#{2,5}) ", r"#\1 ", text, flags=re.MULTILINE)


def render(release):
    tag = release["tag_name"]
    date = release["published_at"][:10]
    out = [f"## {tag}\n"]
    out.append(
        f"Released {date}"
        f"{' (pre-release)' if release['prerelease'] else ''}. "
        f"[Release page]({release['html_url']})\n"
    )

    parts = sections(release.get("body") or "")
    for heading in ("## Assets", "## Changelog"):
        if parts.get(heading):
            out.append(f"#{heading}\n")
            out.append(demote(parts[heading]) + "\n")
    return "\n".join(out)


def main():
    header = (
        "# Downloads\n\n"
        "Packages and source tarballs of every release, built by CI and "
        "published on [GitHub Releases]"
        f"(https://github.com/{REPO}/releases).\n"
    )
    try:
        releases = fetch_releases()
    except OSError as e:
        if os.environ.get("GITHUB_ACTIONS"):
            raise
        print(f"WARNING: cannot fetch releases: {e}", file=sys.stderr)
        releases = []

    with mkdocs_gen_files.open("downloads.md", "w") as f:
        f.write(header + "\n")
        if not releases:
            f.write(
                f"See [all releases](https://github.com/{REPO}/releases).\n"
            )
        for release in releases:
            f.write(render(release) + "\n")


main()
