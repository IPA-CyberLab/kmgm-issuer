#!/bin/bash

BASEURL="https://raw.githubusercontent.com/cert-manager/cert-manager/refs/heads/master/deploy/crds/"
FILES=(
    cert-manager.io_certificaterequests.yaml
)

cd "$(dirname "$0")"

for FILE in "${FILES[@]}"; do
    if [ -f "$FILE" ]; then
        echo "File $FILE already exists, skipping..."
        continue
    fi
    echo "Fetching $FILE..."
    curl -sSL "$BASEURL$FILE" -o "$FILE"
done