# “””
GitLab Projects - Language Summary Report

Fetches all projects from a GitLab instance and summarizes
how many projects use each programming language.

Requirements:
pip install requests tabulate

Usage:
python gitlab_language_summary.py
“””

import requests
from collections import defaultdict
from tabulate import tabulate

# ─────────────────────────────────────────────

# CONFIGURATION — update these before running

# ─────────────────────────────────────────────

GITLAB_URL   = “https://gitlab.example.com”   # e.g. https://gitlab.com or your self-hosted URL
PRIVATE_TOKEN = “your_personal_access_token”  # GitLab → User Settings → Access Tokens
PER_PAGE     = 100                             # Max allowed by GitLab API

# ─────────────────────────────────────────────

def get_all_projects(session: requests.Session) -> list[dict]:
“”“Fetch every project visible to the token (handles pagination).”””
projects = []
page = 1

```
print("Fetching projects", end="", flush=True)

while True:
    response = session.get(
        f"{GITLAB_URL}/api/v4/projects",
        params={
            "per_page": PER_PAGE,
            "page": page,
            "membership": False,   # Set True to limit to projects you are a member of
            "archived": False,     # Skip archived repos
            "statistics": False,
        },
    )
    response.raise_for_status()

    batch = response.json()
    if not batch:
        break

    projects.extend(batch)
    print(".", end="", flush=True)

    # GitLab returns x-next-page header; empty means last page
    next_page = response.headers.get("x-next-page", "")
    if not next_page:
        break
    page = int(next_page)

print(f" done. ({len(projects)} projects found)\n")
return projects
```

def get_project_languages(session: requests.Session, project_id: int) -> list[str]:
“”“Return the list of language names detected in a project.”””
response = session.get(
f”{GITLAB_URL}/api/v4/projects/{project_id}/languages”
)

```
# Some projects (empty / no code) return 404 or empty — skip gracefully
if response.status_code == 404:
    return []
response.raise_for_status()

# Response looks like: {"Python": 78.5, "Shell": 21.5}
return list(response.json().keys())
```

def build_language_summary(session: requests.Session, projects: list[dict]) -> dict:
“””
For each project, retrieve its languages and count how many
projects contain each language.
Returns: { “Python”: 42, “Java”: 17, … }
“””
language_count = defaultdict(int)
total = len(projects)

```
for idx, project in enumerate(projects, start=1):
    name = project.get("name_with_namespace", project["id"])
    print(f"  [{idx:>4}/{total}] {name}", flush=True)

    languages = get_project_languages(session, project["id"])
    for lang in languages:
        language_count[lang] += 1

return dict(language_count)
```

def print_report(language_count: dict, total_projects: int) -> None:
“”“Print a sorted summary table to the console.”””
if not language_count:
print(“No languages detected across any project.”)
return

```
# Sort by project count descending, then alphabetically
sorted_langs = sorted(language_count.items(), key=lambda x: (-x[1], x[0]))

rows = []
for rank, (lang, count) in enumerate(sorted_langs, start=1):
    percentage = (count / total_projects) * 100
    rows.append([rank, lang, count, f"{percentage:.1f}%"])

print("\n" + "=" * 55)
print(f"  LANGUAGE SUMMARY  ({total_projects} total projects scanned)")
print("=" * 55)
print(tabulate(
    rows,
    headers=["#", "Language", "Projects", "% of Total"],
    tablefmt="github"
))
print("=" * 55)
print(f"  Unique languages detected: {len(sorted_langs)}")
print("=" * 55 + "\n")
```

def save_csv(language_count: dict, total_projects: int, filename=“language_summary.csv”) -> None:
“”“Optionally save results to a CSV file.”””
import csv

```
sorted_langs = sorted(language_count.items(), key=lambda x: (-x[1], x[0]))

with open(filename, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Language", "Project Count", "Percentage"])
    for lang, count in sorted_langs:
        writer.writerow([lang, count, f"{(count / total_projects) * 100:.1f}%"])

print(f"CSV saved → {filename}")
```

def main():
session = requests.Session()
session.headers.update({
“PRIVATE-TOKEN”: PRIVATE_TOKEN,
“Content-Type”: “application/json”,
})

```
# 1. Get all projects
projects = get_all_projects(session)
if not projects:
    print("No projects found. Check your token and GITLAB_URL.")
    return

# 2. Build language → project count map
print("Scanning languages per project …\n")
language_count = build_language_summary(session, projects)

# 3. Print the report
print_report(language_count, len(projects))

# 4. Save to CSV (comment out if not needed)
save_csv(language_count, len(projects))
```

if **name** == “**main**”:
main()