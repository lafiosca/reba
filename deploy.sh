#!/bin/bash

# "set -e" makes it so if any step fails, the script aborts:
set -e

# Change to the directory of the script
cd "${BASH_SOURCE%/*}"

# Include config variables
source ./config.sh

if [[ $S3PathConfigBackups ]]
then
	remoteConfig=${S3PathConfigBackups}/config.$(date -Iseconds).ts
	echo "Backing up local config to ${remoteConfig}"
	aws s3 cp src/config.ts ${remoteConfig}
	echo "Backing up local config to ${S3PathConfigBackups}/config.ts"
	aws s3 cp src/config.ts ${S3PathConfigBackups}/config.ts
fi

echo "Building Lambda code"
yarn build

echo "Packaging SAM template (loading Lambda zip to S3 location)"
aws cloudformation package \
	--template-file sam-template.json \
	--output-template-file sam-output.yml \
	--s3-bucket "${S3BucketArtifacts}" \
	--s3-prefix "${S3PrefixArtifacts}"

echo "Deploying CloudFormation stack ${StackName}"
aws cloudformation deploy \
	--template-file sam-output.yml \
	--stack-name "${StackName}" \
	--capabilities CAPABILITY_IAM \
	--parameter-overrides \
	S3BucketEmail="${S3BucketEmail}" \
	S3PrefixEmail="${S3PrefixEmail}"
