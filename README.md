# s3-credentials

[![PyPI](https://img.shields.io/pypi/v/s3-credentials.svg)](https://pypi.org/project/s3-credentials/)
[![Changelog](https://img.shields.io/github/v/release/simonw/s3-credentials?include_prereleases&label=changelog)](https://github.com/simonw/s3-credentials/releases)
[![Tests](https://github.com/simonw/s3-credentials/workflows/Test/badge.svg)](https://github.com/simonw/s3-credentials/actions?query=workflow%3ATest)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/simonw/s3-credentials/blob/master/LICENSE)

A tool for creating credentials for accessing S3 buckets

For project background, see [s3-credentials: a tool for creating credentials for S3 buckets](https://simonwillison.net/2021/Nov/3/s3-credentials/) on my blog.

## ⚠️ Warning

I am not an AWS security expert. You shoud review how this tool works carefully before using it against with own AWS account.

If you are an AWS security expert I would [love to get your feedback](https://github.com/simonw/s3-credentials/issues/7)!

## Installation

Install this tool using `pip`:

    $ pip install s3-credentials

## Configuration

This tool uses [boto3](https://boto3.amazonaws.com/) under the hood which supports [a number of different ways](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html) of providing your AWS credentials.

If you have an existing `~/.aws/config` or `~/.aws/credentials` file the tool will use that.

You can set the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables before calling this tool.

You can also use the `--access-key=`, `--secret-key=`, `--session-token` and `--auth` options documented below.

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
Use `--format ini` to output the credentials in INI format, suitable for pasting into a `~/.aws/credentials` file:
```
% s3-credentials create static.niche-museums.com --format ini > ini.txt
Created user: s3.read-write.static.niche-museums.com with permissions boundary: arn:aws:iam::aws:policy/AmazonS3FullAccess
Attached policy s3.read-write.static.niche-museums.com to user s3.read-write.static.niche-museums.com
Created access key for user: s3.read-write.static.niche-museums.com
% cat ini.txt
aws_access_key_id=AKIAWXFXAIOZKGXI4PVO
aws_secret_access_key=...
````
The `create` command has several additional options:

- `--format TEXT`: The output format to use. Defaults to `json`, but can also be `ini`.
- `--username TEXT`: The username to use for the user that is created by the command (or the username of an existing user if you do not want to create a new one). If ommitted a default such as `s3.read-write.static.niche-museums.com` will be used.
- `-c, --create-bucket`: Create the buckts if they do not exist. Without this any missing buckets will be treated as an error.
- `--read-only`: The user should only be allowed to read files from the bucket.-
- `--write-only`: The user should only be allowed to write files to the bucket, but not read them. This is useful for logging use-cases.
- `--policy filepath-or-string`: A custom policy document (as a file path, literal JSON string or `-` for standard input) - see below
- `--bucket-region`: If creating buckets, the region in which they should be created.
- `--silent`: Don't output details of what is happening, just output the JSON for the created access credentials at the end.
- `--user-permissions-boundary`: Custom [permissions boundary](https://docs.aws.amazon.com`/IAM/latest/UserGuide/access_policies_boundaries.html) to use for users created by this tool. This will default to restricting those users to only interacting with S3, taking the `--read-only` option into account. Use `none` to create users without any permissions boundary at all.

Here's the full sequence of events that take place when you run this command:

1. Confirm that each of the specified buckets exists. If they do not and `--create-bucket` was passed create them - otherwise exit with an error.
2. If a username was not specified, determine a username using the `s3.$permission.$buckets` format.
3. If a user with that username does not exist, create one with an S3 permissions boundary that respects the `--read-only` option - unless `--user-permissions-boundary=none` was passed (or a custom permissions boundary string).
4. For each specified bucket, add an inline IAM policy to the user that gives them permission to either read-only, write-only or read-write against that bucket.
5. Create a new access key for that user and output the key and its secret to the console.

### Using a custom policy

The policy documents applied by this tool can be seen in [policies.py](https://github.com/simonw/s3-credentials/blob/main/s3_credentials/policies.py). If you want to use a custom policy document you can do so using the `--policy` option.

First, create your policy document as a JSON file that looks something like this:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject*", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::$!BUCKET_NAME!$",
        "arn:aws:s3:::$!BUCKET_NAME!$/*"
      ],
    }
  ]
}
```
Note the `$!BUCKET_NAME!$` strings - these will be replaced with the name of the relevant S3 bucket before the policy is applied.

Save that as `custom-policy.json` and apply it using the following command:

    % s3-credentials create my-s3-bucket \
        --policy custom-policy.json

You can also pass `-` to read from standard input, or you can pass the literal JSON string directly to the `--policy` option:
```
% s3-credentials create my-s3-bucket --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject*", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::$!BUCKET_NAME!$",
        "arn:aws:s3:::$!BUCKET_NAME!$/*"
      ],
    }
  ]
}'
```

## Other commands

### whoami

To see which user you are authenticated as:

    s3-credentials whoami

This will output JSON representing the currently authenticated user.

### list-users

To see a list of all users that exist for your AWS account:

    s3-credentials list-users

This will return pretty-printed JSON objects by default.

Add `--nl` to collapse these to single lines as valid newline-delimited JSON.

Add `--array` to output a valid JSON array of objects instead.

### list-buckets

Shows a list of all buckets in your AWS account.

    % s3-credentials list-buckets
    {
        "Name": "aws-cloudtrail-logs-462092780466-f2c900d3",
        "CreationDate": "2021-03-25 22:19:54+00:00"
    }
    {
        "Name": "simonw-test-bucket-for-s3-credentials",
        "CreationDate": "2021-11-03 21:46:12+00:00"
    }

With no extra arguments this will show all available buckets - you can also add one or more explicit bucket names to see just those buckets:

    % s3-credentials list-buckets simonw-test-bucket-for-s3-credentials
    {
        "Name": "simonw-test-bucket-for-s3-credentials",
        "CreationDate": "2021-11-03 21:46:12+00:00"
    }

This accepts the same `--nl` and `--array` options as `list-users`.

Add `--details` to include details of the bucket ACL, website configuration and public access block settings. This is useful for running a security audit of your buckets.

Using `--details` adds three additional API calls for each bucket, so it is advisable to use it with one or more explicit bucket names.
```
% s3-credentials list-buckets simonw-test-public-website-bucket --details
{
  "Name": "simonw-test-public-website-bucket",
  "CreationDate": "2021-11-08 22:53:30+00:00",
  "bucket_acl": {
    "Owner": {
      "DisplayName": "simon",
      "ID": "abcdeabcdeabcdeabcdeabcdeabcde0001"
    },
    "Grants": [
      {
        "Grantee": {
          "DisplayName": "simon",
          "ID": "abcdeabcdeabcdeabcdeabcdeabcde0001",
          "Type": "CanonicalUser"
        },
        "Permission": "FULL_CONTROL"
      }
    ]
  },
  "public_access_block": null,
  "bucket_website": {
    "IndexDocument": {
      "Suffix": "index.html"
    },
    "ErrorDocument": {
      "Key": "error.html"
    }
  }
}
```
A bucket with `public_access_block` might look like this:
```json
{
  "Name": "aws-cloudtrail-logs-462092780466-f2c900d3",
  "CreationDate": "2021-03-25 22:19:54+00:00",
  "bucket_acl": {
    "Owner": {
      "DisplayName": "simon",
      "ID": "abcdeabcdeabcdeabcdeabcdeabcde0001"
    },
    "Grants": [
      {
        "Grantee": {
          "DisplayName": "simon",
          "ID": "abcdeabcdeabcdeabcdeabcdeabcde0001",
          "Type": "CanonicalUser"
        },
        "Permission": "FULL_CONTROL"
      }
    ]
  },
  "public_access_block": {
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  },
  "bucket_website": null
}
```

### list-user-policies

To see a list of inline policies belonging to users:

```
% s3-credentials list-user-policies s3.read-write.static.niche-museums.com

User: s3.read-write.static.niche-museums.com
PolicyName: s3.read-write.static.niche-museums.com
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::static.niche-museums.com"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "s3:*Object",
      "Resource": [
        "arn:aws:s3:::static.niche-museums.com/*"
      ]
    }
  ]
}
```
You can pass any number of usernames here. If you don't specify a username the tool will loop through every user belonging to your account:

    s3-credentials list-user-policies

### delete-user

In trying out this tool it's possible you will create several different user accounts that you later decide to clean up.

Deleting AWS users is a little fiddly: you first need to delete their access keys, then their inline policies and finally the user themselves.

The `s3-credentials delete-user` handles this for you:

```
% s3-credentials delete-user s3.read-write.simonw-test-bucket-10
User: s3.read-write.simonw-test-bucket-10
  Deleted policy: s3.read-write.simonw-test-bucket-10
  Deleted access key: AKIAWXFXAIOZK3GPEIWR
  Deleted user
```
You can pass it multiple usernames to delete multiple users at a time.

## Common options

All of the `s3-credentials` commands also accept the following options for authenticating against AWS:

- `--access-key`: AWS access key ID
- `--secret-key`: AWS secret access key
- `--session-token`: AWS session token
- `--endpoint-url`: Custom endpoint URL
- `--auth`: file (or `-` for standard input) containing credentials to use

The file passed to `--auth` can be either a JSON file or an INI file. JSON files should contain the following:

```json
{
    "AccessKeyId": "AKIAWXFXAIOZA5IR5PY4",
    "SecretAccessKey": "g63..."
}
```
The JSON file can also optionally include a session token in a `"SessionToken"` key.

The INI format variant of this file should look like this:

```ini
[default]
aws_access_key_id=AKIAWXFXAIOZNCR2ST7S
aws_secret_access_key=g63...
```
Any section headers will do - the tool will use the information from the first section it finds in the file which has a `aws_access_key_id` key.

These auth file formats are the same as those that can be created using the `create` command.

## Tips

You can see a log of changes made by this tool using AWS CloudTrail - the following link should provide an Event History interface showing revelant changes made to your AWS account such as `CreateAccessKey`, `CreateUser`, `PutUserPolicy` and more:

https://console.aws.amazon.com/cloudtrail/home

You can view a list of your S3 buckets and confirm that they have the desired permissions and properties here:

https://console.aws.amazon.com/s3/home

The managiment interface for an individual bucket is at `https://console.aws.amazon.com/s3/buckets/NAME-OF-BUCKET`

## Development

To contribute to this tool, first checkout the code. Then create a new virtual environment:

    cd s3-credentials
    python -m venv venv
    source venv/bin/activate

Or if you are using `pipenv`:

    pipenv shell

Now install the dependencies and test dependencies:

    pip install -e '.[test]'

To run the tests:

    pytest

### Integration tests

The main tests all use stubbed interfaces to AWS, so will not make any outbound API calls.

There is also a suite of integration tests in `tests/test_integration.py` which DO make API calls to AWS, using credentials from your environment variables or `~/.aws/credentials` file.

These tests are skipped by default. If you have AWS configured with an account that has permission to run `s3-credentials` (create users, roles, buckets etc) you can run these tests using:

    pytest --integration

The tests will create a number of different users and buckets and should then delete them once they finish running.
