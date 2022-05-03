#!/bin/bash

# "set -e" makes it so if any step fails, the script aborts:
set -e

# Change to the directory of the script
cd "${BASH_SOURCE%/*}"

# Include config variables
source ./config.sh

if [[ $S3PathConfigBackups ]]
then
	remoteConfig=${S3PathConfigBackups}/config.ts
	localBackupConfig=src/config.$(date -Iseconds).ts
	echo "Backing up local config to ${localBackupConfig}"
	cp src/config.ts ${localBackupConfig}
	echo "Copying remote config from ${remoteConfig}"
	aws s3 cp ${remoteConfig} src/config.ts
fi

