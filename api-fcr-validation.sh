#!/usr/bin/env bash

set -euo pipefail

# ==============================
# Colors
# ==============================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ==============================
# Config (from env or defaults)
# ==============================
TIMEOUT="${TIMEOUT:-5}"
RETRIES="${RETRIES:-3}"

# ==============================
# Logging
# ==============================
log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# ==============================
# Netcat check (port level)
# ==============================
check_port() {
  local name=$1
  local host=$2
  local port=$3

  log_info "Checking TCP connectivity: $name ($host:$port)"

  for i in $(seq 1 $RETRIES); do
    if nc -z -w $TIMEOUT "$host" "$port"; then
      log_success "$name reachable on $host:$port"
      return 0
    else
      log_warn "Retry $i/$RETRIES failed for $name ($host:$port)"
      sleep 2
    fi
  done

  log_error "$name NOT reachable on $host:$port"
  return 1
}

# ==============================
# Curl check (HTTP/HTTPS level)
# ==============================
check_http() {
  local name=$1
  local url=$2

  log_info "Checking HTTP connectivity: $name ($url)"

  for i in $(seq 1 $RETRIES); do
    STATUS=$(curl -k -o /dev/null -s -w "%{http_code}" --connect-timeout $TIMEOUT "$url" || true)

    if [[ "$STATUS" =~ ^2|3 ]]; then
      log_success "$name reachable (HTTP $STATUS)"
      return 0
    else
      log_warn "Retry $i/$RETRIES failed for $name (HTTP $STATUS)"
      sleep 2
    fi
  done

  log_error "$name NOT reachable (Last HTTP $STATUS)"
  return 1
}

# ==============================
# VALIDATION LIST
# ==============================
FAILED=0

# ---- Nexus ----
check_port "Nexus" "$NEXUS_HOST" "$NEXUS_PORT" || FAILED=1
check_http "Nexus" "$NEXUS_URL" || FAILED=1

# ---- Artifactory ----
check_port "Artifactory" "$ARTIFACTORY_HOST" "$ARTIFACTORY_PORT" || FAILED=1
check_http "Artifactory" "$ARTIFACTORY_URL" || FAILED=1

# ---- Terraform Registry ----
check_port "Terraform" "$TERRAFORM_HOST" "$TERRAFORM_PORT" || FAILED=1
check_http "Terraform" "$TERRAFORM_URL" || FAILED=1

# ==============================
# Final Result
# ==============================
if [ "$FAILED" -eq 1 ]; then
  log_error "Firewall connectivity validation FAILED"
  exit 1
else
  log_success "All connectivity checks PASSED"
fi