#!/bin/bash -e


: "${BRANCHES_TO_MERGE_REGEX?}" "${BRANCH_TO_MERGE?}"
: "${GITHUB_SECRET_TOKEN?}" "${GITHUB_REPO?}" "${REPO_TEMP?}"

export GIT_COMMITTER_EMAIL='travis@travis'
export GIT_COMMITTER_NAME='Travis CI'

if ! grep -q "$BRANCHES_TO_MERGE_REGEX" <<< "$TRAVIS_BRANCH"; then
    printf "Current branch %s doesn't match regex %s, exiting\\n" \
        "$TRAVIS_BRANCH" "$BRANCHES_TO_MERGE_REGEX" >&2
    exit 0
fi

## Since Travis does a partial checkout, we need to get the whole thing
#git clone "https://github.com/$GITHUB_REPO" "$REPO_TEMP"
#
## shellcheck disable=SC2164
#printf 'cd %s\n' "$REPO_TEMP" >&2
#cd "$REPO_TEMP"
#
#printf 'Checking out %s\n' "$BRANCHES_TO_MERGE_REGEX" >&2
#git checkout "$BRANCHES_TO_MERGE_REGEX"

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
