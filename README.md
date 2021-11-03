# s3-credentials

[![PyPI](https://img.shields.io/pypi/v/s3-credentials.svg)](https://pypi.org/project/s3-credentials/)
[![Changelog](https://img.shields.io/github/v/release/simonw/s3-credentials?include_prereleases&label=changelog)](https://github.com/simonw/s3-credentials/releases)
[![Tests](https://github.com/simonw/s3-credentials/workflows/Test/badge.svg)](https://github.com/simonw/s3-credentials/actions?query=workflow%3ATest)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/simonw/s3-credentials/blob/master/LICENSE)

A tool for creating credentials for accessing S3 buckets

## ⚠️ Warning

I am not an AWS security expert. You shoud review how this tool works carefully before using it against with own AWS account.

If you are an AWS security expert I would [love to get your feedback](https://github.com/simonw/s3-credentials/issues/7)!

## Installation

Install this tool using `pip`:

    $ pip install s3-credentials

## Usage

The `s3-credentials create` command is the core feature of this tool. Pass it one or more S3 bucket names and it will create a new user with permission to access just those specific buckets, then create access credentials for that user and output them to your console.

Make sure to record the `SecretAccessKey` because it will only be displayed once and cannot be recreated later on.

In this example I create credentials for reading and writing files in my `static.niche-museums.com` S3 bucket:

```
% s3-credentials create static.niche-museums.com
Created user: s3.read-write.static.niche-museums.com with permissions boundary: arn:aws:iam::aws:policy/AmazonS3FullAccess
Attached policy s3.read-write.static.niche-museums.com to user s3.read-write.static.niche-museums.com
Created access key for user: s3.read-write.static.niche-museums.com
{
    "UserName": "s3.read-write.static.niche-museums.com",
    "AccessKeyId": "AKIAWXFXAIOZOYLZAEW5",
    "Status": "Active",
    "SecretAccessKey": "...",
    "CreateDate": "2021-11-03 01:38:24+00:00"
}
```
The command has several additional options:

- `--username TEXT`: The username to use for the user that is created by the command (or the username of an existing user if you do not want to create a new one). If ommitted a default such as `s3.read-write.static.niche-museums.com` will be used.
- `-c, --create-bucket`: Create the buckts if they do not exist. Without this any missing buckets will be treated as an error.
- `--read-only`: The user should only be allowed to read files from the bucket.-
- `--write-only`: The user should only be allowed to write files to the bucket, but not read them. This is useful for logging use-cases.
- `--bucket-region`: If creating buckets, the region in which they should be created.
- `--silent`: Don't output details of what is happening, just output the JSON for the created access credentials at the end.
`--user-permissions-boundary`: Custom [permissions boundary](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html) to use for users created by this tool. This will default to restricting those users to only interacting with S3, taking the `--read-only` option into account. Use `none` to create users without any permissions boundary at all.

Here's the full sequence of events that take place when you run this command:

1. Confirm that each of the specified buckets exists. If they do not and `--create-bucket` was passed create them - otherwise exit with an error.
2. If a username was not specified, determine a username using the `s3.$permission.$buckets` format.
3. If a user with that username does not exist, create one with an S3 permissions boundary that respects the `--read-only` option - unless `--user-permissions-boundary=none` was passed (or a custom permissions boundary string).
4. For each specified bucket, add an inline IAM policy to the user that gives them permission to either read-only, write-only or read-write against that bucket.
5. Create a new access key for that user and output the key and its secret to the console.

## Other commands

### whoami

To see which user you are authenticated as:

    $ s3-credentials whoami

This will output JSON representing the currently authenticated user.

### list-users

To see a list of all users that exist for your AWS account:

    $ s3-credentials list-users

This will return pretty-printed JSON objects by default.

Add `--nl` to collapse these to single lines as valid newline-delimited JSON.

Add `--array` to output a valid JSON array of objects instead.

## Development

To contribute to this tool, first checkout the code. Then create a new virtual environment:

    cd s3-credentials
    python -mvenv venv
    source venv/bin/activate

Or if you are using `pipenv`:

    pipenv shell

Now install the dependencies and test dependencies:

    pip install -e '.[test]'

To run the tests:

    pytest
