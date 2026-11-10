#!/usr/bin/env bash
# Publishes files to a GitHub release, replacing its assets in place.
#
# The release and its tag are never deleted: deleting the tag and recreating it
# straight away races with GitHub, which may then turn the new release into an
# untagged draft whose assets can not be downloaded.
#
# Usage: publish_release.sh TAG TITLE NOTES FILE...
set -euo pipefail

TAG=$1
TITLE=$2
NOTES=$3
shift 3

if gh release view "$TAG" >/dev/null 2>&1; then
  gh release edit "$TAG" --title "$TITLE" --notes "$NOTES" --latest=false
else
  gh release create "$TAG" --title "$TITLE" --notes "$NOTES" --latest=false
fi

gh release upload "$TAG" "$@" --clobber

# Remove the assets left by the previous runs (markers, obsolete versions).
for asset in $(gh release view "$TAG" --json assets --jq '.assets[].name'); do
  keep=false
  for file in "$@"; do
    if [ "$(basename "$file")" = "$asset" ]; then
      keep=true
    fi
  done
  if [ "$keep" = false ]; then
    gh release delete-asset "$TAG" "$asset" --yes
  fi
done
