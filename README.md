# reba
## Virtual domain mail delivery for SES

This is a simple Lambda function for enhancing AWS SES with similar functionality to Postfix's virtual alias domains.

The documentation for this project is incomplete. At some point, I hope to finish it and write a blog article. For
now, certain advanced users may still find the code and instructions below handy.

## Deployment

1. Install and configure the AWS CLI, yarn, and git.
2. Clone this repository.
3. Copy `config.sh.example` to `config.sh` and replace the required values:
	* `StackName`: the name of the AWS CloudFormation stack to create during deployment (default: "Reba")
	* `S3BucketArtifacts`: the name of the S3 bucket where your Lambda code zip artifacts will be stored during deployment
	* `S3PrefixArtifacts`: the prefix within that S3 bucket for storing the code artifacts (default: "cloudformation/reba")
	* `S3BucketEmail`: the name of the S3 bucket that you will configure SES to store the raw emails in for processing.
	* `S3PrefixEmail`: the prefix within that S3 bucket for storing the email (default: "ses/forwarding/")
	* `S3PathConfigBackups`: an optional S3 path for storing a dated backup copy of the latest config.ts upon deployment
4. Copy `src/config.example.ts` to `src/config.ts` and edit it with your domain alias rules.
5. Run `./deploy.sh` to package and deploy the function to AWS.

If all goes well, the function will be ready. If you log into the AWS console, you should find a CloudFormation stack
named `Reba` (or whatever you changed the `StackName` to in `config.sh`). This stack should contain a Lambda function
named `<StackName>-ProcessEmail`. Then you will need to configure your incoming SES rules to execute the function.

## SES Email Receiving Rules

There are various ways to configure SES depending on your goals. What follows is one possible configuration. Assume
that you have already configured SES to receive mail for your domain `mydomain.com`. You could then add a rule for
that domain to your currently active SES Email Receiving Rule Set (first creating a new rule set if necessary) with
the following configuration:

* Enabled: checked
* Enable spam and virus scanning: checked
* Recipient: mydomain.com
* Actions:
	1. **S3**: specify the same bucket and prefix that you configured for deployment
	2. **Lambda**: choose the `<StackName>-ProcessEmail` function created by deployment
	3. **Bounce**: choose the "550 5.1.1 Mailbox does not exist" template and specify `postmaster@mydomain.com` as the reply sender
