stages:
  # keep your existing stages here; e.g. build/test/etc.
  - collect

merge_csv_artifacts:
  stage: collect
  image: alpine:3.20
  variables:
    # OUTPUT
    OUT_CSV: "merged.csv"
    # Only pick CSVs with this pattern (inside each artifact .zip). Adjust if you want to narrow further.
    CSV_GLOB: "*.csv"
    # Set to a regex to limit which jobs’ artifacts are considered (e.g., "^test-").
    JOB_NAME_REGEX: ".*"
    # Consider only successful jobs' artifacts. Set to "false" to include others.
    REQUIRE_SUCCESS_ONLY: "true"
    # Add a column with source job name to the merged CSV
    ADD_SOURCE_COLUMN: "true"
  before_script:
    - apk add --no-cache curl jq unzip python3 coreutils
  script:
    - set -euo pipefail
    - |
      echo "Project: $CI_PROJECT_ID  Pipeline: $CI_PIPELINE_ID"
      API="$CI_SERVER_URL/api/v4"
      TMP="$(mktemp -d)"
      CSV_DIR="$TMP/csvs"
      mkdir -p "$CSV_DIR"

      # 1) List all jobs in this pipeline (paginate up to 1000 by stepping pages; easy to extend)
      #    Filters: success-only if requested; otherwise get all finished jobs.
      page=1
      all_jobs="[]"
      while : ; do
        if [ "${REQUIRE_SUCCESS_ONLY}" = "true" ]; then
          qs="scope[]=success"
        else
          # include all states; GitLab allows multiple scope params; you can customize if needed
          qs="scope[]=success&scope[]=failed&scope[]=canceled&scope[]=manual"
        fi
        resp="$(curl -sfSL \
          -H "JOB-TOKEN: ${CI_JOB_TOKEN}" \
          "${API}/projects/${CI_PROJECT_ID}/pipelines/${CI_PIPELINE_ID}/jobs?per_page=100&${qs}&page=${page}")"
        count="$(echo "$resp" | jq 'length')"
        if [ "$count" -eq 0 ]; then break; fi
        all_jobs="$(jq -s 'add' <(echo "$all_jobs") <(echo "$resp"))"
        page=$((page+1))
        if [ $page -gt 10 ]; then break; fi   # safety cap: 1000 jobs
      done

      echo "Found $(echo "$all_jobs" | jq 'length') jobs in scope."

      # 2) Filter by name regex and presence of artifacts, then download artifacts ZIPs
      echo "$all_jobs" | jq -r '.[] | select(.name|test(env.JOB_NAME_REGEX)) | select(.artifacts_file and .artifacts_file.filename != null) | "\(.id),\(.name)"' \
      | while IFS=, read -r jid jname; do
          echo "Downloading artifacts from job #$jid ($jname)"
          zip_path="$TMP/${jid}.zip"
          if curl -sfSL -H "JOB-TOKEN: ${CI_JOB_TOKEN}" \
               -o "$zip_path" \
               "${API}/projects/${CI_PROJECT_ID}/jobs/${jid}/artifacts" ; then
            :
          else
            echo "WARN: No artifacts for job #$jid ($jname) or download failed. Skipping."
            rm -f "$zip_path" || true
            continue
          fi

          # 3) Extract only CSVs matching CSV_GLOB; flatten paths
          # List entries first so we can filter by glob case-insensitively
          mapfile -t csv_entries < <(unzip -Z1 "$zip_path" | awk 'BEGIN{IGNORECASE=1} { if ($0 ~ /\.csv$/) print $0 }')
          if [ "${#csv_entries[@]}" -eq 0 ]; then
            echo "No CSV files in job #$jid artifacts."
            rm -f "$zip_path"
            continue
          fi

          for entry in "${csv_entries[@]}"; do
            # Check again against CSV_GLOB (supports simple patterns)
            case "$(basename "$entry")" in
              $CSV_GLOB)
                # Extract to CSV_DIR with a unique filename to avoid collisions
                base="$(basename "$entry")"
                out="${CSV_DIR}/${jid}__${jname//[^A-Za-z0-9_.-]/_}__${base}"
                unzip -p "$zip_path" "$entry" > "$out"
                echo "Extracted: $out"
                ;;
            esac
          done

          rm -f "$zip_path"
        done

      echo "Total CSVs extracted: $(ls -1 "$CSV_DIR"/*.csv 2>/dev/null | wc -l || true)"

      # 4) Merge CSVs (same header assumed). We add an optional Source_Job column.
      #    If headers differ, rows still append; ensure your producers align schemas.
      python3 - <<'PY'
import csv, glob, os, sys

csv_dir = os.environ.get("CSV_DIR", "") or sys.argv[1] if len(sys.argv) > 1 else ""
if not csv_dir:
    print("ERROR: CSV_DIR not set", file=sys.stderr)
    sys.exit(1)

out_path = os.environ.get("OUT_CSV", "merged.csv")
add_source = (os.environ.get("ADD_SOURCE_COLUMN", "true").lower() == "true")

files = sorted(glob.glob(os.path.join(csv_dir, "*.csv")))
if not files:
    print("No CSVs found to merge.")
    # still create an empty file with just header? We'll create an empty file.
    open(out_path, "w").close()
    sys.exit(0)

# Read header from first file
with open(files[0], newline='', encoding='utf-8', errors='replace') as f:
    r = csv.reader(f)
    first_header = next(r, [])

out_header = first_header.copy()
if add_source:
    out_header.append("Source_Job")

written_header = False
rows = 0

with open(out_path, "w", newline="", encoding="utf-8") as out_fp:
    w = csv.writer(out_fp)
    w.writerow(out_header)
    written_header = True

    for path in files:
        # Derive job name from file naming convention: <jobid>__<jobname>__<basename>
        fname = os.path.basename(path)
        parts = fname.split("__", 2)
        source_job = parts[1] if len(parts) >= 3 else ""

        with open(path, newline='', encoding='utf-8', errors='replace') as f:
            r = csv.reader(f)
            header = next(r, [])
            # If header lengths differ, we will pad/truncate to first_header length
            for row in r:
                row = list(row)
                # Normalize row length to the first header's length
                if len(row) < len(first_header):
                    row += [""] * (len(first_header) - len(row))
                elif len(row) > len(first_header):
                    row = row[:len(first_header)]
                if add_source:
                    row.append(source_job)
                w.writerow(row)
                rows += 1

print(f"Merged {len(files)} files into {out_path} with {rows} rows.")
PY
  artifacts:
    when: always
    expire_in: 7 days
    paths:
      - merged.csv
  # If your 100 jobs are in the *same* stage and finish together, no explicit needs are required.
  # If you want this job to start only after those jobs complete, ensure this stage comes after them in `stages`.
  rules:
    - if: $CI_PIPELINE_SOURCE   # always run for any pipeline source
