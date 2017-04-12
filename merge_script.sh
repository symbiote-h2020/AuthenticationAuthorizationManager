#!/bin/bash -e

: "${GITHUB_SECRET_TOKEN?}" "${GITHUB_REPO?}"

export GIT_COMMITTER_EMAIL='travis@travis'
export GIT_COMMITTER_NAME='Travis CI'

printf 'Removing staging branch as it has been handled already\n'
printf 'git push %s :staging >/dev/null 2>&1\n' "$GITHUB_REPO"
push_uri="https://$GITHUB_SECRET_TOKEN@github.com/$GITHUB_REPO"
git push "$push_uri" :staging >/dev/null 2>&1

# Preparing for merge
git checkout staging
git config user.email "$GIT_COMMITTER_EMAIL"
git config user.name "$GIT_COMMITTER_NAME"

printf 'Pulling develop\n' >&2
git fetch origin +develop:develop
git merge develop --no-edit