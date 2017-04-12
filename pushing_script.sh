#!/bin/bash -e

: "${GITHUB_SECRET_TOKEN?}" "${GITHUB_REPO?}" 

## shellcheck disable=SC2164

push_uri="https://$GITHUB_SECRET_TOKEN@github.com/$GITHUB_REPO"

# Redirect to /dev/null to avoid secret leakage
printf 'git push %s staging:develop >/dev/null 2>&1\n' "$GITHUB_REPO"
git push "$push_uri" staging:develop >/dev/null 2>&1