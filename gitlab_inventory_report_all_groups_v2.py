#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GitLab Project Inventory Report (All Groups, with --group-name)
---------------------------------------------------------------

Features:
- Scan ALL groups in an instance (everything visible to the token), or
- Scan a SINGLE group when --group-name is provided (path or numeric ID).
- Excludes archived projects.
- Generates a CSV with project metadata for migration analysis.

Columns:
- Project ID
- Project Name
- Group Name
- Project Link
- Project Topic(s)
- Deployment Environments
- GitLab CI Config Present
- Pipeline Executed
- Containerization  ("container" if Dockerfile exists, else "not container")
- Codebase Structure Summary  (root folder names, comma-separated)
- Primary Language
- Build Tool Used
- SQL Files Present
- Deployment Job Name(s)

Usage:
  python gitlab_inventory_report_all_groups_v2.py --base-url https://gitlab.example.com --token <PAT> --out report.csv
  python gitlab_inventory_report_all_groups_v2.py --base-url https://gitlab.example.com --token <PAT> --group-name mygroup/subgroup --out report.csv

Optional flags:
  --scan-scope my|all     -> 'my' (default) lists groups visible to the token holder.
                             'all' sets all_available=true (requires admin token) to scan all instance groups.
  --group-contains TEXT   -> when scanning many groups, include only those whose full_path contains TEXT.
  --max-groups N          -> limit number of groups processed (for testing).

Env vars alternative:
  GITLAB_BASE_URL, GITLAB_TOKEN

Logs to STDOUT and gitlab_inventory_report_all_groups_v2.log
"""

import argparse
import base64
import csv
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Dict

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ------------------------- Logging Setup -------------------------
LOGGER = logging.getLogger("gitlab_inventory_report_all_groups_v2")
LOGGER.setLevel(logging.INFO)
_console = logging.StreamHandler(sys.stdout)
_console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
LOGGER.addHandler(_console)
_file = logging.FileHandler("gitlab_inventory_report_all_groups_v2.log", mode="a", encoding="utf-8")
_file.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
LOGGER.addHandler(_file)

# ------------------------- Data Classes -------------------------
@dataclass
class ProjectRow:
    project_id: int
    project_name: str
    group_name: str
    project_link: str
    project_topics: str
    deployment_environments: str
    gitlab_ci_config_present: str  # Yes/No
    pipeline_executed: str         # Yes/No
    containerization: str          # container / not container
    codebase_structure_summary: str
    primary_language: str
    build_tool_used: str
    sql_files_present: str         # Yes/No
    deployment_job_names: str

# ------------------------- HTTP Session with Retries -------------------------
def make_session(token: str, timeout: int = 30) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "PRIVATE-TOKEN": token,
        "Accept": "application/json",
        "User-Agent": "gitlab-inventory-report/2.1"
    })
    retries = Retry(
        total=5,
        backoff_factor=0.6,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.request_timeout = timeout
    return session

def api_get(session: requests.Session, url: str, params: Optional[dict] = None) -> requests.Response:
    try:
        resp = session.get(url, params=params, timeout=getattr(session, "request_timeout", 30))
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", "3"))
            LOGGER.warning(f"429 Too Many Requests. Sleeping {retry_after}s then retrying: {url}")
            time.sleep(retry_after)
            resp = session.get(url, params=params, timeout=getattr(session, "request_timeout", 30))
        resp.raise_for_status()
        return resp
    except requests.RequestException as e:
        snippet = ""
        try:
            snippet = resp.text[:500] if 'resp' in locals() and hasattr(resp, 'text') else ""
        except Exception:
            pass
        LOGGER.error(f"GET failed: {url} params={params} error={e} body_snippet={snippet}")
        raise

def paginate(session: requests.Session, url: str, params: Optional[dict] = None):
    per_page = 100
    page = 1
    params = dict(params or {})
    params.setdefault("per_page", per_page)
    while True:
        params["page"] = page
        resp = api_get(session, url, params=params)
        data = resp.json()
        if not isinstance(data, list):
            yield data
            break
        if not data:
            break
        for item in data:
            yield item
        next_page = resp.headers.get("X-Next-Page")
        if not next_page:
            break
        page = int(next_page) if next_page.isdigit() else page + 1

# ------------------------- Repo / Project helpers -------------------------
def get_default_branch(project: dict) -> Optional[str]:
    return project.get("default_branch")

def join_list(values: List[str]) -> str:
    return ", ".join(sorted(set([v for v in values if v])))

def detect_build_tool(file_paths: List[str]) -> str:
    lower = [p.lower() for p in file_paths]
    basenames = [os.path.basename(p) for p in lower]
    if "pom.xml" in basenames:
        return "Maven"
    if any(b in ("build.gradle", "build.gradle.kts") for b in basenames):
        return "Gradle"
    if "package.json" in basenames:
        return "Node/npm"
    if any(b in ("requirements.txt", "setup.py", "pyproject.toml") for b in basenames):
        return "Python/pip"
    if any(b.endswith(".sln") or b.endswith(".csproj") for b in basenames):
        return "Dotnet"
    if "go.mod" in basenames:
        return "Go"
    if any(p.endswith(".sh") for p in lower):
        return "Bash"
    if any(p.endswith(".yml") or p.endswith(".yaml") for p in lower):
        return "YAML-only"
    return "Unknown"

def collect_all_paths(session: requests.Session, base_url: str, project_id: int, ref: str) -> List[str]:
    paths: List[str] = []
    url = f"{base_url}/api/v4/projects/{project_id}/repository/tree"
    page = 1
    while True:
        resp = api_get(session, url, params={"ref": ref, "recursive": True, "per_page": 100, "page": page})
        items = resp.json()
        if not items:
            break
        for it in items:
            if it.get("type") == "blob" and it.get("path"):
                paths.append(it["path"])
        next_page = resp.headers.get("X-Next-Page")
        if not next_page:
            break
        page = int(next_page) if next_page.isdigit() else page + 1
    return paths

def file_exists(session: requests.Session, base_url: str, project_id: int, ref: str, filepath: str) -> bool:
    """Return True if file exists at ref. Treat 404 as "no" without logging errors."""
    url = f"{base_url}/api/v4/projects/{project_id}/repository/files/{requests.utils.quote(filepath, safe='')}"
    try:
        resp = session.get(url, params={"ref": ref}, timeout=getattr(session, "request_timeout", 30))
        if resp.status_code == 200:
            return True
        if resp.status_code == 404:
            return False
        if resp.status_code == 429:
            time.sleep(int(resp.headers.get("Retry-After", "3")))
            resp = session.get(url, params={"ref": ref}, timeout=getattr(session, "request_timeout", 30))
            return resp.status_code == 200
        return False
    except Exception:
        return False

def get_file_yaml(session: requests.Session, base_url: str, project_id: int, ref: str, filepath: str) -> Optional[dict]:
    url = f"{base_url}/api/v4/projects/{project_id}/repository/files/{requests.utils.quote(filepath, safe='')}"
    try:
        resp = api_get(session, url, params={"ref": ref})
        data = resp.json()
        content = data.get("content")
        if not content:
            return None
        raw = base64.b64decode(content).decode("utf-8", errors="replace")
        import yaml
        return yaml.safe_load(raw)
    except Exception as e:
        LOGGER.debug(f"YAML parse failed for {filepath} in project {project_id}: {e}")
        return None

def detect_deployment_jobs(ci_yaml: Optional[dict]) -> List[str]:
    if not isinstance(ci_yaml, dict):
        return []
    jobs: List[str] = []
    for job_name, job_def in ci_yaml.items():
        if not isinstance(job_def, dict):
            continue
        stage = str(job_def.get("stage", "")).lower()
        has_env = "environment" in job_def
        if has_env or "deploy" in stage or job_name.lower().startswith("deploy"):
            jobs.append(str(job_name))
    return sorted(set(jobs))

def has_any_pipeline(session: requests.Session, base_url: str, project_id: int) -> bool:
    url = f"{base_url}/api/v4/projects/{project_id}/pipelines"
    try:
        resp = api_get(session, url, params={"per_page": 1})
        arr = resp.json()
        return isinstance(arr, list) and len(arr) > 0
    except Exception:
        return False

def get_environments(session: requests.Session, base_url: str, project_id: int) -> List[str]:
    url = f"{base_url}/api/v4/projects/{project_id}/environments"
    envs: List[str] = []
    try:
        for item in paginate(session, url, params={"per_page": 100}):
            if isinstance(item, dict) and "name" in item:
                envs.append(item["name"])
    except Exception as e:
        LOGGER.debug(f"Failed to list environments for project {project_id}: {e}")
    return sorted(set(envs))

def get_languages(session: requests.Session, base_url: str, project_id: int) -> str:
    url = f"{base_url}/api/v4/projects/{project_id}/languages"
    try:
        resp = api_get(session, url)
        data = resp.json()
        if isinstance(data, dict) and data:
            primary = max(data.items(), key=lambda kv: kv[1])[0]
            return primary
    except Exception as e:
        LOGGER.debug(f"Failed to get languages for project {project_id}: {e}")
    return "Unknown"

def get_group_name(project: dict) -> str:
    ns = project.get("namespace") or {}
    return ns.get("full_path") or ns.get("name") or ""

def list_root_tree(session: requests.Session, base_url: str, project_id: int, ref: Optional[str]) -> List[dict]:
    if not ref:
        return []
    url = f"{base_url}/api/v4/projects/{project_id}/repository/tree"
    try:
        resp = api_get(session, url, params={"ref": ref, "per_page": 100})
        data = resp.json()
        return data if isinstance(data, list) else []
    except Exception as e:
        LOGGER.debug(f"Failed to get root tree for project {project_id}: {e}")
        return []

def build_project_row(session: requests.Session, base_url: str, project: dict) -> ProjectRow:
    pid = project["id"]
    name = project.get("name") or ""
    link = project.get("web_url") or ""
    topics = join_list(project.get("topics") or [])
    group_name = get_group_name(project)
    default_branch = get_default_branch(project)
    if not default_branch:
        LOGGER.info(f"Project {pid} has no default branch; skipping repository scans.")
    environments = join_list(get_environments(session, base_url, pid))

    ci_present = "No"
    ci_yaml = None
    if default_branch:
        if file_exists(session, base_url, pid, default_branch, ".gitlab-ci.yml"):
            ci_present = "Yes"
            ci_yaml = get_file_yaml(session, base_url, pid, default_branch, ".gitlab-ci.yml")
        elif file_exists(session, base_url, pid, default_branch, ".gitlab-ci.yaml"):
            ci_present = "Yes"
            ci_yaml = get_file_yaml(session, base_url, pid, default_branch, ".gitlab-ci.yaml")

    had_pipeline = "Yes" if has_any_pipeline(session, base_url, pid) else "No"

    # Containerization: 'container' if Dockerfile exists, else 'not container'
    containerization = "not container"
    if default_branch:
        docker_candidates = ["Dockerfile", "docker/Dockerfile", "deploy/Dockerfile", "build/Dockerfile"]
        if any(file_exists(session, base_url, pid, default_branch, fp) for fp in docker_candidates):
            containerization = "container"
        else:
            try:
                all_paths = collect_all_paths(session, base_url, pid, default_branch)
                if any(os.path.basename(p).lower() == "dockerfile" for p in all_paths):
                    containerization = "container"
            except Exception:
                pass

    # Codebase structure (root folders: names only)
    root_tree = list_root_tree(session, base_url, pid, default_branch)
    root_folders = [item.get("name") for item in root_tree if item.get("type") == "tree"]
    codebase_structure_summary = join_list(root_folders)

    primary_language = get_languages(session, base_url, pid)

    # Build tool + SQL detection
    build_tool = "Unknown"
    sql_present = "No"
    if default_branch:
        try:
            all_paths = collect_all_paths(session, base_url, pid, default_branch)
            build_tool = detect_build_tool(all_paths)
            if any(p.lower().endswith(".sql") for p in all_paths):
                sql_present = "Yes"
        except Exception as e:
            LOGGER.debug(f"Failed scanning tree for project {pid}: {e}")

    deployment_jobs = join_list(detect_deployment_jobs(ci_yaml) if ci_yaml else [])

    return ProjectRow(
        project_id=pid,
        project_name=name,
        group_name=group_name,
        project_link=link,
        project_topics=topics,
        deployment_environments=environments,
        gitlab_ci_config_present=ci_present,
        pipeline_executed=had_pipeline,
        containerization=containerization,
        codebase_structure_summary=codebase_structure_summary,
        primary_language=primary_language,
        build_tool_used=build_tool,
        sql_files_present=sql_present,
        deployment_job_names=deployment_jobs,
    )

def write_csv(rows: List[ProjectRow], out_path: str) -> None:
    fieldnames = [
        "Project ID",
        "Project Name",
        "Group Name",
        "Project Link",
        "Project Topic(s)",
        "Deployment Environments",
        "GitLab CI Config Present",
        "Pipeline Executed",
        "Containerization",
        "Codebase Structure Summary",
        "Primary Language",
        "Build Tool Used",
        "SQL Files Present",
        "Deployment Job Name(s)",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({
                "Project ID": r.project_id,
                "Project Name": r.project_name,
                "Group Name": r.group_name,
                "Project Link": r.project_link,
                "Project Topic(s)": r.project_topics,
                "Deployment Environments": r.deployment_environments,
                "GitLab CI Config Present": r.gitlab_ci_config_present,
                "Pipeline Executed": r.pipeline_executed,
                "Containerization": r.containerization,
                "Codebase Structure Summary": r.codebase_structure_summary,
                "Primary Language": r.primary_language,
                "Build Tool Used": r.build_tool_used,
                "SQL Files Present": r.sql_files_present,
                "Deployment Job Name(s)": r.deployment_job_names,
            })

# ------------------------- Group discovery -------------------------
def list_all_groups(session: requests.Session, base_url: str, scope: str = "my", name_contains: Optional[str] = None, max_groups: Optional[int] = None) -> List[dict]:
    """List groups visible to the token. If scope='all', use all_available=true (requires admin)."""
    url = f"{base_url}/api/v4/groups"
    params: Dict[str, object] = {"per_page": 100}
    if scope == "all":
        params["all_available"] = True
    groups: List[dict] = []
    for g in paginate(session, url, params=params):
        if not isinstance(g, dict) or "id" not in g:
            continue
        if name_contains and name_contains.lower() not in (g.get("full_path") or g.get("path") or "").lower():
            continue
        groups.append(g)
        if max_groups and len(groups) >= max_groups:
            break
    return groups

def get_single_group(session: requests.Session, base_url: str, group_name_or_id: str) -> Optional[dict]:
    """Fetch a single group by full_path (preferred) or ID."""
    url = f"{base_url}/api/v4/groups/{requests.utils.quote(group_name_or_id, safe='')}"
    try:
        resp = api_get(session, url)
        data = resp.json()
        if isinstance(data, dict) and "id" in data:
            return data
    except Exception as e:
        LOGGER.error(f"Failed to fetch group '{group_name_or_id}': {e}")
    return None

def discover_projects_in_group(session: requests.Session, base_url: str, group_id: str) -> List[dict]:
    projects: List[dict] = []
    url = f"{base_url}/api/v4/groups/{group_id}/projects"
    for item in paginate(session, url, params={"include_subgroups": True, "with_shared": False, "archived": False, "per_page": 100}):
        if isinstance(item, dict) and "id" in item:
            projects.append(item)

    subgroups_url = f"{base_url}/api/v4/groups/{group_id}/subgroups"
    subgroup_ids: List[int] = []
    for sg in paginate(session, subgroups_url, params={"per_page": 100}):
        if isinstance(sg, dict) and "id" in sg:
            subgroup_ids.append(sg["id"])

    for sgid in subgroup_ids:
        url_sg = f"{base_url}/api/v4/groups/{sgid}/projects"
        for item in paginate(session, url_sg, params={"per_page": 100, "archived": False}):
            if isinstance(item, dict) and "id" in item:
                projects.append(item)

    seen = set()
    unique: List[dict] = []
    for p in projects:
        pid = p.get("id")
        if pid not in seen:
            seen.add(pid)
            unique.append(p)
    return unique

# ------------------------- CLI & Main -------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate GitLab project inventory CSV across groups, with optional single-group mode.")
    parser.add_argument("--base-url", default=os.getenv("GITLAB_BASE_URL"), required=not bool(os.getenv("GITLAB_BASE_URL")), help="GitLab base URL, e.g. https://gitlab.com or https://gitlab.example.com")
    parser.add_argument("--token", default=os.getenv("GITLAB_TOKEN"), required=not bool(os.getenv("GITLAB_TOKEN")), help="GitLab personal access token with read_api scope (admin for --scan-scope all)")
    parser.add_argument("--out", default="gitlab_projects_report_all_groups_v2.csv", help="Output CSV path")
    parser.add_argument("--scan-scope", choices=["my", "all"], default="my", help="Group visibility scope: 'my' (default) or 'all' (admin only)")
    parser.add_argument("--group-name", default=None, help="Scan only this group (full_path like 'parent/child' or numeric ID). If omitted, scans many groups per --scan-scope.")
    parser.add_argument("--group-contains", default=None, help="When scanning multiple groups, include only groups whose full_path contains this text (case-insensitive)")
    parser.add_argument("--max-groups", type=int, default=None, help="Limit number of groups to process (testing)")
    return parser.parse_args()

def main():
    args = parse_args()
    base_url = args.base_url.rstrip("/")
    token = args.token
    out_csv = args.out

    session = make_session(token)

    all_rows: List[ProjectRow] = []
    processed_projects = 0

    if args.group_name:
        grp = get_single_group(session, base_url, args.group_name)
        if not grp:
            LOGGER.error(f"Group '{args.group_name}' not found or not accessible.")
            sys.exit(2)
        groups = [grp]
        LOGGER.info(f"Processing single group: {grp.get('full_path') or grp.get('path') or grp.get('id')}")
    else:
        LOGGER.info(f"Listing groups (scope={args.scan_scope}) at {base_url} ...")
        try:
            groups = list_all_groups(session, base_url, scope=args.scan_scope, name_contains=args.group_contains, max_groups=args.max_groups)
            LOGGER.info(f"Found {len(groups)} group(s) to process.")
        except Exception as e:
            LOGGER.error(f"Failed to list groups: {e}")
            sys.exit(2)

    for gi, grp in enumerate(groups, start=1):
        gid = grp.get("id")
        gpath = grp.get("full_path") or grp.get("path") or str(gid)
        LOGGER.info(f"[{gi}/{len(groups)}] Processing group id={gid} path='{gpath}'")
        try:
            projects = discover_projects_in_group(session, base_url, str(gid))
            LOGGER.info(f"  -> {len(projects)} project(s) discovered in group '{gpath}' (archived excluded)")
        except Exception as e:
            LOGGER.error(f"Failed to discover projects for group {gid} ({gpath}): {e}")
            continue

        for idx, proj in enumerate(projects, start=1):
            processed_projects += 1
            try:
                LOGGER.info(f"  [{idx}/{len(projects)} | total {processed_projects}] Project id={proj.get('id')} name='{proj.get('name')}'")
                row = build_project_row(session, base_url, proj)
                all_rows.append(row)
            except Exception as e:
                LOGGER.error(f"  Error processing project id={proj.get('id')} name='{proj.get('name')}': {e}")

    try:
        write_csv(all_rows, out_csv)
        LOGGER.info(f"Wrote CSV report: {out_csv} (projects: {len(all_rows)})")
    except Exception as e:
        LOGGER.error(f"Failed writing CSV '{out_csv}': {e}")
        sys.exit(3)

if __name__ == "__main__":
    main()
