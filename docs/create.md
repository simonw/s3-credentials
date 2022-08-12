# Creating S3 credentials

The `s3-credentials create` command is the core feature of this tool. Pass it one or more S3 bucket names, specify a policy (read-write, read-only or write-only) and it will return AWS credentials that can be used to access those buckets.

These credentials can be **temporary** or **permanent**.

- Temporary credentials can last for between 15 minutes and 12 hours. They are created using [STS.AssumeRole()](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).
- Permanent credentials never expire. They are created by first creating a dedicated AWS user, then assigning a policy to that user and creating and returning an access key for it.

Make sure to record the `SecretAccessKey` because it will only be displayed once and cannot be recreated later on.

In this example I create permanent credentials for reading and writing files in my `static.niche-museums.com` S3 bucket:

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
If you add `--format ini` the credentials will be output in INI format, suitable for pasting into a `~/.aws/credentials` file:
```
% s3-credentials create static.niche-museums.com --format ini > ini.txt
Created user: s3.read-write.static.niche-museums.com with permissions boundary: arn:aws:iam::aws:policy/AmazonS3FullAccess
Attached policy s3.read-write.static.niche-museums.com to user s3.read-write.static.niche-museums.com
Created access key for user: s3.read-write.static.niche-museums.com
% cat ini.txt
[default]
aws_access_key_id=AKIAWXFXAIOZKGXI4PVO
aws_secret_access_key=...
```

To create temporary credentials, add `--duration 15m` (or `1h` or `1200s`). The specified duration must be between 15 minutes and 12 hours.

```
% s3-credentials create static.niche-museums.com --duration 15m
Assume role against arn:aws:iam::462092780466:role/s3-credentials.AmazonS3FullAccess for 900s
{
    "AccessKeyId": "ASIAWXFXAIOZPAHAYHUG",
    "SecretAccessKey": "Nrnoc...",
    "SessionToken": "FwoGZXIvYXd...mr9Fjs=",
    "Expiration": "2021-11-11 03:24:07+00:00"
}
```
When using temporary credentials the session token must be passed in addition to the access key and secret key.

The `create` command has a number of options:

- `--format TEXT`: The output format to use. Defaults to `json`, but can also be `ini`.
- `--duration 15m`: For temporary credentials, how long should they last? This can be specified in seconds, minutes or hours using a suffix of `s`, `m` or `h` - but must be between 15 minutes and 12 hours.
- `--username TEXT`: The username to use for the user that is created by the command (or the username of an existing user if you do not want to create a new one). If ommitted a default such as `s3.read-write.static.niche-museums.com` will be used.
- `-c, --create-bucket`: Create the buckets if they do not exist. Without this any missing buckets will be treated as an error.
- `--prefix my-prefix/`: Credentials should only allow access to keys in the S3 bucket that start with this prefix.
- `--public`: When creating a bucket, set it so that any file uploaded to that bucket can be downloaded by anyone who knows its filename. This attaches the {ref}`public_bucket_policy`.
- `--website`: Sets the bucket to public and configures it to act as a website, with `index.html` treated as an index page and `error.html` used to display custom errors. The URL for the website will be `http://<bucket-name>.s3-website.<region>.amazonaws.com/` - the region defaults to `us-east-1` unless you specify a `--bucket-region`.
- `--read-only`: The user should only be allowed to read files from the bucket.
- `--write-only`: The user should only be allowed to write files to the bucket, but not read them. This can be useful for logging and backups.
- `--policy filepath-or-string`: A custom policy document (as a file path, literal JSON string or `-` for standard input) - see below.
- `--statement json-statement`: Custom JSON statement block to be added to the generated policy.
- `--bucket-region`: If creating buckets, the region in which they should be created.
- `--silent`: Don't output details of what is happening, just output the JSON for the created access credentials at the end.
- `--dry-run`: Output details of AWS changes that would have been made without applying them.
- `--user-permissions-boundary`: Custom [permissions boundary](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html) to use for users created by this tool. The default is to restrict those users to only interacting with S3, taking the `--read-only` option into account. Use `none` to create users without any permissions boundary at all.

## Changes that will be made to your AWS account

How the tool works varies depending on if you are creating temporary or permanent credentials.

For permanent credentials, the steps are as follows:

1. Confirm that each of the specified buckets exists. If they do not and `--create-bucket` was passed create them - otherwise exit with an error.
2. If a username was not specified, derive a username using the `s3.$permission.$buckets` format.
3. If a user with that username does not exist, create one with an S3 permissions boundary of [AmazonS3ReadOnlyAccess](https://github.com/glassechidna/trackiam/blob/master/policies/AmazonS3ReadOnlyAccess.json) for `--read-only` or [AmazonS3FullAccess](https://github.com/glassechidna/trackiam/blob/master/policies/AmazonS3FullAccess.json) otherwise - unless `--user-permissions-boundary=none` was passed, or a custom permissions boundary string.
4. For each specified bucket, add an inline IAM policy to the user that gives them permission to either read-only, write-only or read-write against that bucket.
5. Create a new access key for that user and output the key and its secret to the console.

For temporary credentials:

1. Confirm or create buckets, in the same way as for permanent credentials.
2. Check if an AWS role called `s3-credentials.AmazonS3FullAccess` exists. If it does not exist create it, configured to allow the user's AWS account to assume it and with the `arn:aws:iam::aws:policy/AmazonS3FullAccess` policy attached.
3. Use `STS.AssumeRole()` to return temporary credentials that are restricted to just the specified buckets and specified read-only/read-write/write-only policy.

You can run the `create` command with the `--dry-run` option to see a summary of changes that would be applied, including details of generated policy documents, without actually applying those changes.

## Using a custom policy

The policy documents applied by this tool [are listed here](policy-documents.md).

If you want to use a custom policy document you can do so using the `--policy` option.

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
You can also specify one or more extra statement blocks that should be added to the generated policy, using `--statement JSON`. This example enables the AWS `textract:` APIs for the generated credentials, useful for using with the [s3-ocr](https://datasette.io/tools/s3-ocr) tool:
```
% s3-credentials create my-s3-bucket --statement '{
  "Effect": "Allow",
  "Action": "textract:*",
  "Resource": "*"
}'
```
