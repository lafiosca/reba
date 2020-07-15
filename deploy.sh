#!/bin/bash

# "set -e" makes it so if any step fails, the script aborts:
set -e

# Change to the directory of the script
cd "${BASH_SOURCE%/*}"

# Include config variables
source ./config.sh

if [[ $S3PathConfigBackups ]]
then
	aws s3 cp src/config.ts ${S3PathConfigBackups}/config.$(date -Iseconds).ts
fi

# Build Lambda package
yarn build

# Package SAM template (loads Lambda dist zips to S3 locations)
aws cloudformation package \
	--template-file sam-template.json \
	--output-template-file sam-output.yml \
	--s3-bucket "${S3BucketArtifacts}" \
	--s3-prefix "${S3PrefixArtifacts}"

# Deploy CloudFormation stack
aws cloudformation deploy \
	--template-file sam-output.yml \
	--stack-name "${StackName}" \
	--capabilities CAPABILITY_IAM \
	--parameter-overrides \
	S3BucketEmail="${S3BucketEmail}" \
	S3PrefixEmail="${S3PrefixEmail}"
