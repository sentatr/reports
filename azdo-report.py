# “””
Azure DevOps Server - Git Repository Tag Report

Scans ALL collections → ALL projects → ALL Git repositories
and maps each repo to its parent project’s tags.

Output: CSV with columns:
Collection | Project | Repository | Repo Clone URL | Tag Key | Tag Value

Usage:
python azdo_repo_tag_report.py

Configuration:
Set the variables in the CONFIG section below, or use environment variables.

Requirements:
pip install requests pandas
“””

import os
import sys
import csv
import logging
from datetime import datetime

import requests
import pandas as pd
from requests.auth import HTTPBasicAuth

# ─────────────────────────────────────────────

# CONFIG — edit these or set as env variables

# ─────────────────────────────────────────────

AZDO_SERVER_URL = os.environ.get(“AZDO_SERVER_URL”, “https://azdo.mycompany.com”)  # No trailing slash
PAT             = os.environ.get(“AZDO_PAT”, “YOUR_PERSONAL_ACCESS_TOKEN”)
OUTPUT_FILE     = os.environ.get(“AZDO_OUTPUT_FILE”, f”azdo_repo_tag_report_{datetime.now().strftime(’%Y%m%d_%H%M%S’)}.csv”)
LOG_LEVEL       = os.environ.get(“LOG_LEVEL”, “INFO”)   # DEBUG for verbose output

# ─────────────────────────────────────────────

logging.basicConfig(
level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
format=”%(asctime)s [%(levelname)s] %(message)s”,
handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger(**name**)

def make_session(pat: str) -> requests.Session:
“”“Create a requests session with PAT auth and JSON headers.”””
session = requests.Session()
session.auth = HTTPBasicAuth(””, pat)
session.headers.update({“Accept”: “application/json”})
return session

def api_get(session: requests.Session, url: str, params: dict = None) -> dict:
“”“GET wrapper with error handling.”””
try:
resp = session.get(url, params=params, timeout=30)
resp.raise_for_status()
return resp.json()
except requests.exceptions.HTTPError as e:
log.warning(f”HTTP error {resp.status_code} for {url}: {e}”)
return {}
except requests.exceptions.RequestException as e:
log.warning(f”Request failed for {url}: {e}”)
return {}

def get_collections(session: requests.Session, server_url: str) -> list[dict]:
“””
Fetch all project collections from the AzDO Server.
Endpoint: GET {server}/_apis/projectcollections?api-version=7.1
“””
url = f”{server_url}/_apis/projectcollections”
data = api_get(session, url, params={“api-version”: “7.1”})
collections = data.get(“value”, [])
log.info(f”Found {len(collections)} collection(s)”)
return collections

def get_projects(session: requests.Session, server_url: str, collection_name: str) -> list[dict]:
“””
Fetch all projects within a collection.
Endpoint: GET {server}/{collection}/_apis/projects?api-version=7.1
“””
url = f”{server_url}/{collection_name}/_apis/projects”
projects = []
skip = 0
page_size = 100

```
while True:
    data = api_get(session, url, params={
        "api-version": "7.1",
        "$top": page_size,
        "$skip": skip
    })
    batch = data.get("value", [])
    projects.extend(batch)
    if len(batch) < page_size:
        break
    skip += page_size

log.info(f"  Collection '{collection_name}': {len(projects)} project(s)")
return projects
```

def parse_tag_strings(raw_tags: list[str]) -> list[dict]:
“””
Parse a list of raw tag name strings into {key, value} dicts.
Handles formats seen in AzDO UI:
- “AppInfo:11538-CRF”   → key=AppInfo,      value=11538-CRF
- “TMT:Scott Simpson”   → key=TMT,           value=Scott Simpson
- “TPO:Jason Yu”        → key=TPO,           value=Jason Yu
- “Inactive”            → key=Inactive,      value=Inactive  (flag-style tag)
- “AppID=1243”          → key=AppID,         value=1243
“””
parsed = []
for name in raw_tags:
name = name.strip()
if not name:
continue
if “:” in name:
key, _, value = name.partition(”:”)
parsed.append({“key”: key.strip(), “value”: value.strip()})
elif “=” in name:
key, _, value = name.partition(”=”)
parsed.append({“key”: key.strip(), “value”: value.strip()})
else:
# Flag-style tag with no value (e.g. “Inactive”)
parsed.append({“key”: name, “value”: name})
return parsed

def get_project_tags(session: requests.Session, server_url: str, collection_name: str, project_id: str) -> list[dict]:
“””
Fetch project-level tags as shown in the AzDO UI ‘About this project’ panel.

```
AzDO Server stores these via the Project Properties API. Tags are stored
under the property key "System.TeamProject.Tags" as a semicolon-delimited string,
OR returned directly as a 'tags' field on the project detail endpoint.

Strategy (3-level fallback):
  1. GET {collection}/_apis/projects/{projectId}?includeCapabilities=true
     → check project.tags[] array (AzDO Services style)
  2. GET {collection}/_apis/projects/{projectId}/properties
     → look for "System.TeamProject.Tags" property (semicolon-delimited string)
  3. GET {collection}/_apis/tagging/scopes/{projectId}/tags  (legacy fallback)
"""
parsed = []

# ── Strategy 1: project detail with tags array ──────────────────────────
url1 = f"{server_url}/{collection_name}/_apis/projects/{project_id}"
data1 = api_get(session, url1, params={"api-version": "7.1", "includeCapabilities": "true"})
if data1:
    # Some AzDO versions return tags as a list of strings directly on the project object
    tags_list = data1.get("tags", [])
    if isinstance(tags_list, list) and tags_list:
        log.debug(f"    [Strategy 1] Project {project_id}: tags={tags_list}")
        parsed = parse_tag_strings(tags_list)
        if parsed:
            return parsed

    # Also check capabilities → tagNames (seen in some versions)
    caps = data1.get("capabilities", {})
    tag_names = caps.get("versioncontrol", {}).get("tagNames", [])
    if not tag_names:
        tag_names = caps.get("processTemplate", {}).get("tagNames", [])
    if tag_names:
        log.debug(f"    [Strategy 1b] Project {project_id}: tagNames={tag_names}")
        parsed = parse_tag_strings(tag_names)
        if parsed:
            return parsed

# ── Strategy 2: project properties API ──────────────────────────────────
url2 = f"{server_url}/{collection_name}/_apis/projects/{project_id}/properties"
data2 = api_get(session, url2, params={"api-version": "7.1-preview"})
if data2:
    props = data2.get("value", [])
    for prop in props:
        pname = prop.get("name", "")
        pval  = prop.get("value", "")
        # The UI tags are stored under this well-known property key
        if pname in ("System.TeamProject.Tags", "Microsoft.TeamFoundation.Project.Tags"):
            if isinstance(pval, str) and pval.strip():
                # Tags are semicolon-separated: "AppInfo:11538-CRF;TMT:Scott Simpson;Inactive"
                raw = [t.strip() for t in pval.split(";") if t.strip()]
                log.debug(f"    [Strategy 2] Project {project_id}: raw props tags={raw}")
                parsed = parse_tag_strings(raw)
                if parsed:
                    return parsed

# ── Strategy 3: legacy work-item tagging API (last resort) ──────────────
url3 = f"{server_url}/{collection_name}/_apis/tagging/scopes/{project_id}/tags"
data3 = api_get(session, url3, params={"api-version": "7.1-preview", "includeInactive": "false"})
if data3:
    raw_tags = [t.get("name", "") for t in data3.get("value", [])]
    if raw_tags:
        log.debug(f"    [Strategy 3] Project {project_id}: legacy tags={raw_tags}")
        parsed = parse_tag_strings(raw_tags)
        if parsed:
            return parsed

log.debug(f"    Project {project_id}: no tags found across all strategies")
return []
```

def get_repos(session: requests.Session, server_url: str, collection_name: str, project_id: str) -> list[dict]:
“””
Fetch all Git repositories for a project.
Endpoint: GET {server}/{collection}/{project}/_apis/git/repositories?api-version=7.1
“””
url = f”{server_url}/{collection_name}/{project_id}/_apis/git/repositories”
data = api_get(session, url, params={“api-version”: “7.1”})
repos = data.get(“value”, [])
log.debug(f”    Project {project_id}: {len(repos)} repo(s)”)
return repos

def build_report(session: requests.Session, server_url: str) -> list[dict]:
“””
Main logic: walk collections → projects → repos → tags
Returns list of row dicts for CSV output.
“””
rows = []
collections = get_collections(session, server_url)

```
if not collections:
    log.error("No collections returned. Check your AZDO_SERVER_URL and PAT permissions.")
    sys.exit(1)

for col in collections:
    col_name = col.get("name", "")
    col_id   = col.get("id", "")
    if not col_name:
        log.warning(f"Skipping collection with no name: {col}")
        continue

    log.info(f"Processing collection: {col_name}")
    projects = get_projects(session, server_url, col_name)

    for proj in projects:
        proj_name = proj.get("name", "")
        proj_id   = proj.get("id", "")
        if not proj_name:
            continue

        log.debug(f"  Processing project: {proj_name}")

        # Get project-level tags
        tags = get_project_tags(session, server_url, col_name, proj_id)

        # Get all Git repos under this project
        repos = get_repos(session, server_url, col_name, proj_id)

        if not repos:
            log.debug(f"    No repos found in project '{proj_name}', skipping.")
            continue

        for repo in repos:
            repo_name      = repo.get("name", "")
            repo_clone_url = repo.get("remoteUrl", repo.get("sshUrl", ""))

            if tags:
                # One row per tag (repo appears multiple times if multi-tagged)
                for tag in tags:
                    rows.append({
                        "Collection":     col_name,
                        "Project":        proj_name,
                        "Repository":     repo_name,
                        "Repo Clone URL": repo_clone_url,
                        "Tag Key":        tag["key"],
                        "Tag Value":      tag["value"],
                    })
            else:
                # No tags on project → Unknown
                rows.append({
                    "Collection":     col_name,
                    "Project":        proj_name,
                    "Repository":     repo_name,
                    "Repo Clone URL": repo_clone_url,
                    "Tag Key":        "Unknown",
                    "Tag Value":      "Unknown",
                })

return rows
```

def write_csv(rows: list[dict], output_file: str):
“”“Write report rows to CSV using pandas for clean formatting.”””
if not rows:
log.warning(“No data collected. CSV will not be written.”)
return

```
df = pd.DataFrame(rows, columns=[
    "Collection", "Project", "Repository", "Repo Clone URL", "Tag Key", "Tag Value"
])

df.to_csv(output_file, index=False, encoding="utf-8-sig")  # utf-8-sig for Excel compatibility
log.info(f"\n{'='*60}")
log.info(f"Report written to: {output_file}")
log.info(f"Total rows       : {len(df)}")
log.info(f"Unique repos     : {df[['Collection','Project','Repository']].drop_duplicates().shape[0]}")
log.info(f"Unique projects  : {df[['Collection','Project']].drop_duplicates().shape[0]}")
log.info(f"Unique collections: {df['Collection'].nunique()}")
log.info(f"{'='*60}\n")
```

def main():
log.info(“Azure DevOps Server — Git Repo Tag Report”)
log.info(f”Server  : {AZDO_SERVER_URL}”)
log.info(f”Output  : {OUTPUT_FILE}”)

```
if PAT == "YOUR_PERSONAL_ACCESS_TOKEN":
    log.error("PAT is not set. Please set AZDO_PAT environment variable or edit the CONFIG section.")
    sys.exit(1)

session = make_session(PAT)
rows    = build_report(session, AZDO_SERVER_URL)
write_csv(rows, OUTPUT_FILE)
```

if **name** == “**main**”:
main()