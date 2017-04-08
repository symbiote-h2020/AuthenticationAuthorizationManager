#!/bin/bash -e


: "${GITHUB_SECRET_TOKEN?}" "${GITHUB_REPO?}"

export GIT_COMMITTER_EMAIL='travis@travis'
export GIT_COMMITTER_NAME='Travis CI'

printf 'Removing staging from %s\n' "$GITHUB_REPO" >&2
push_uri="https://$GITHUB_SECRET_TOKEN@github.com/$GITHUB_REPO"

printf 'git push %s :%s >/dev/null 2>&1' "$GITHUB_REPO" "$TRAVIS_BRANCH"
git push "$push_uri" :"$TRAVIS_BRANCH" >/dev/null 2>&1