# “””
Azure DevOps Server - Tag Diagnostic Script

Tests ALL known tag-related API endpoints against a single project
to find exactly where your UI tags are stored.

Based on your screenshot, project “CorpFin_CRF” has these tags:

- AppInfo:11538-CRF
- TMT:Scott Simpson
- TPO:Jason Yu
- Inactive

Usage:
python azdo_tag_diagnostic.py

Fill in the CONFIG section below with your server, collection, project, and PAT.
“””

import json
import requests
from requests.auth import HTTPBasicAuth

# ─────────────────────────────────────────────────────────────────

# CONFIG — fill these in before running

# ─────────────────────────────────────────────────────────────────

AZDO_SERVER_URL = “https://azdo.mycompany.com”   # e.g. https://azdo.mycompany.com
COLLECTION      = “MyCollection”                  # e.g. DefaultCollection
PROJECT_NAME    = “CorpFin_CRF”                   # exact project name from UI
PAT             = “YOUR_PERSONAL_ACCESS_TOKEN”

# ─────────────────────────────────────────────────────────────────

session = requests.Session()
session.auth = HTTPBasicAuth(””, PAT)
session.headers.update({“Accept”: “application/json”})

DIVIDER = “=” * 70

def get(url, params=None):
“”“Safe GET — always returns (status_code, json_or_text).”””
try:
r = session.get(url, params=params, timeout=30)
try:
body = r.json()
except Exception:
body = r.text
return r.status_code, body
except Exception as e:
return 0, str(e)

def show(label, status, body):
print(f”\n{‘─’*70}”)
print(f”  {label}”)
print(f”  Status : {status}”)
if isinstance(body, dict) or isinstance(body, list):
print(f”  Response:\n{json.dumps(body, indent=2)[:3000]}”)
else:
print(f”  Response:\n{str(body)[:3000]}”)

def step(msg):
print(f”\n{DIVIDER}\n  STEP: {msg}\n{DIVIDER}”)

# ════════════════════════════════════════════════════════════════

print(DIVIDER)
print(”  Azure DevOps Tag Diagnostic”)
print(f”  Server     : {AZDO_SERVER_URL}”)
print(f”  Collection : {COLLECTION}”)
print(f”  Project    : {PROJECT_NAME}”)
print(DIVIDER)

# ── STEP 1: Resolve project ID from name ────────────────────────

step(“1 — Resolve Project ID”)
url = f”{AZDO_SERVER_URL}/{COLLECTION}/_apis/projects/{PROJECT_NAME}”
status, body = get(url, {“api-version”: “7.1”})
show(“GET project by name”, status, body)

project_id = None
if isinstance(body, dict):
project_id = body.get(“id”)
print(f”\n  ✅ Project ID resolved: {project_id}”) if project_id else print(”  ❌ Could not resolve project ID”)

if not project_id:
print(”\n  Cannot continue without a project ID. Check COLLECTION and PROJECT_NAME.”)
exit(1)

# ── STEP 2: Project detail — does it include a ‘tags’ field? ────

step(“2 — Project Detail (includeCapabilities=true)”)
url = f”{AZDO_SERVER_URL}/{COLLECTION}/_apis/projects/{project_id}”
status, body = get(url, {“api-version”: “7.1”, “includeCapabilities”: “true”})
show(“GET project detail”, status, body)

if isinstance(body, dict):
tags_field = body.get(“tags”)
print(f”\n  ‘tags’ field on project object: {tags_field}”)

# ── STEP 3: Project Properties API ──────────────────────────────

step(“3 — Project Properties API”)
url = f”{AZDO_SERVER_URL}/{COLLECTION}/_apis/projects/{project_id}/properties”
for api_ver in [“7.1-preview.1”, “7.1-preview”, “6.0-preview.1”, “5.1-preview.1”]:
status, body = get(url, {“api-version”: api_ver})
show(f”GET project/properties (api-version={api_ver})”, status, body)
if status == 200:
print(”  ✅ This version works — check response above for tag-related properties”)
break
elif status == 404:
print(”  ❌ 404 — endpoint not available in this api-version”)

# ── STEP 4: Legacy Work Item Tagging API ────────────────────────

step(“4 — Legacy Tagging API (/_apis/tagging/scopes/{projectId}/tags)”)
url = f”{AZDO_SERVER_URL}/{COLLECTION}/_apis/tagging/scopes/{project_id}/tags”
status, body = get(url, {“api-version”: “7.1-preview”, “includeInactive”: “false”})
show(“GET tagging/scopes tags”, status, body)

# ── STEP 5: Core APIs — tags on project via _apis/core ──────────

step(“5 — Core project tags endpoint”)
url = f”{AZDO_SERVER_URL}/{COLLECTION}/_apis/core/projects/{project_id}”
status, body = get(url, {“api-version”: “7.1”})
show(“GET _apis/core/projects/{id}”, status, body)

# ── STEP 6: Graph subject lookup (may expose tags) ───────────────

step(“6 — Extensibility / project settings properties”)
url = f”{AZDO_SERVER_URL}/{COLLECTION}/{project_id}/_apis/distributedtask/properties”
status, body = get(url, {“api-version”: “7.1-preview”})
show(“GET distributedtask/properties”, status, body)

# ── STEP 7: REST via project collection (older AzDO Server) ─────

step(“7 — Project tags via older AzDO Server REST endpoint”)
url = f”{AZDO_SERVER_URL}/{COLLECTION}/_apis/projects/{project_id}”
for api_ver in [“4.1”, “5.0”, “5.1”, “6.0”, “7.0”]:
status, body = get(url, {“api-version”: api_ver})
if isinstance(body, dict) and body.get(“tags”):
show(f”GET project (api-version={api_ver}) — HAS TAGS”, status, body)
print(f”  ✅ TAGS FOUND with api-version={api_ver}: {body.get(‘tags’)}”)
break
else:
print(f”  api-version={api_ver} → status={status}, tags={body.get(‘tags’) if isinstance(body, dict) else ‘N/A’}”)

# ── STEP 8: Check raw project list — tags in list response? ─────

step(“8 — Check if tags appear in project list response”)
url = f”{AZDO_SERVER_URL}/{COLLECTION}/_apis/projects”
status, body = get(url, {“api-version”: “7.1”, “$top”: 5})
show(“GET _apis/projects (first 5)”, status, body)
if isinstance(body, dict):
for proj in body.get(“value”, []):
if proj.get(“id”) == project_id:
print(f”\n  ✅ Found target project in list. Tags field: {proj.get(‘tags’)}”)

print(f”\n{DIVIDER}”)
print(”  Diagnostic complete.”)
print(”  Share the output above so we can identify the correct tag endpoint.”)
print(DIVIDER)