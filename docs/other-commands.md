# Other commands

```{contents}
---
local:
class: this-will-duplicate-information-and-it-is-still-useful-here
---
```

## policy

You can use the `s3-credentials policy` command to generate the JSON policy document that would be used without applying it. The command takes one or more required bucket names and a subset of the options available on the `create` command:

- `--read-only` - generate a read-only policy
- `--write-only` - generate a write-only policy
- `--prefix` - policy should be restricted to keys in the bucket that start with this prefix
- `--statement json-statement`: Custom JSON statement block
- `--public-bucket` - generate a bucket policy for a public bucket

With none of these options it defaults to a read-write policy.
```bash
s3-credentials policy my-bucket --read-only
```
```json
{
    "Version": "2012-10-17",
...
```

## whoami

To see which user you are authenticated as:
```bash
s3-credentials whoami
```
This will output JSON representing the currently authenticated user.

Using this with the `--auth` option is useful for verifying created credentials:
```bash
s3-credentials create static.niche-museums.com --read-only > auth.json
```
```bash
s3-credentials whoami --auth auth.json
```
```json
{
    "UserId": "AIDAWXFXAIOZPIZC6MHAG",
    "Account": "462092780466",
    "Arn": "arn:aws:iam::462092780466:user/s3.read-only.static.niche-museums.com"
}
```
## list-users

To see a list of all users that exist for your AWS account:
```bash
s3-credentials list-users
```
This will return a pretty-printed array of JSON objects by default.

Add `--nl` to collapse these to single lines as valid newline-delimited JSON.

Add `--csv` or `--tsv` to get back CSV or TSV data.

## list-buckets

Shows a list of all buckets in your AWS account.

```bash
s3-credentials list-buckets
```
```json
[
  {
    "Name": "aws-cloudtrail-logs-462092780466-f2c900d3",
    "CreationDate": "2021-03-25 22:19:54+00:00"
  },
  {
    "Name": "simonw-test-bucket-for-s3-credentials",
    "CreationDate": "2021-11-03 21:46:12+00:00"
  }
]
```
With no extra arguments this will show all available buckets - you can also add one or more explicit bucket names to see just those buckets:

```bash
s3-credentials list-buckets simonw-test-bucket-for-s3-credentials
```
```json
[
  {
    "Name": "simonw-test-bucket-for-s3-credentials",
    "CreationDate": "2021-11-03 21:46:12+00:00"
  }
]
```
This accepts the same `--nl`, `--csv` and `--tsv` options as `list-users`.

Add `--details` to include details of the bucket ACL, website configuration and public access block settings. This is useful for running a security audit of your buckets.

Using `--details` adds several additional API calls for each bucket, so it is advisable to use it with one or more explicit bucket names.
```bash
s3-credentials list-buckets simonw-test-public-website-bucket --details
```
```json
[
  {
    "Name": "simonw-test-public-website-bucket",
    "CreationDate": "2021-11-08 22:53:30+00:00",
    "region": "us-east-1",
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
      },
      "url": "http://simonw-test-public-website-bucket.s3-website.us-east-1.amazonaws.com/"
    }
  }
]
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

## list-bucket

To list the contents of a bucket, use `list-bucket`:

```bash
s3-credentials list-bucket static.niche-museums.com
```
```json
[
  {
    "Key": "Griffith-Observatory.jpg",
    "LastModified": "2020-01-05 16:51:01+00:00",
    "ETag": "\"a4cff17d189e7eb0c4d3bf0257e56885\"",
    "Size": 3360040,
    "StorageClass": "STANDARD"
  },
  {
    "Key": "IMG_0353.jpeg",
    "LastModified": "2019-10-25 02:50:49+00:00",
    "ETag": "\"d45bab0b65c0e4b03b2ac0359c7267e3\"",
    "Size": 2581023,
    "StorageClass": "STANDARD"
  }
]
```
You can use the `--prefix myprefix/` option to list only keys that start with a specific prefix.

The commmand accepts the same `--nl`, `--csv` and `--tsv` options as `list-users`.

Add `--urls` to include a `URL` field in the output providing the full URL to each object.

## list-user-policies

To see a list of inline policies belonging to users:

```bash
s3-credentials list-user-policies s3.read-write.static.niche-museums.com
```
```
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
```bash
s3-credentials list-user-policies
```
## list-roles

The `list-roles` command lists all of the roles available for the authenticated account.

Add `--details` to fetch the inline and attached managed policies for each row as well - this is slower as it needs to make several additional API calls for each role.

You can optionally add one or more role names to the command to display and fetch details about just those specific roles.

Example usage:

```bash
s3-credentials list-roles AWSServiceRoleForLightsail --details
```
```json
[
  {
    "Path": "/aws-service-role/lightsail.amazonaws.com/",
    "RoleName": "AWSServiceRoleForLightsail",
    "RoleId": "AROAWXFXAIOZG5ACQ5NZ5",
    "Arn": "arn:aws:iam::462092780466:role/aws-service-role/lightsail.amazonaws.com/AWSServiceRoleForLightsail",
    "CreateDate": "2021-01-15 21:41:48+00:00",
    "AssumeRolePolicyDocument": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "Service": "lightsail.amazonaws.com"
          },
          "Action": "sts:AssumeRole"
        }
      ]
    },
    "MaxSessionDuration": 3600,
    "inline_policies": [
      {
        "RoleName": "AWSServiceRoleForLightsail",
        "PolicyName": "LightsailExportAccess",
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "kms:Decrypt",
                "kms:DescribeKey",
                "kms:CreateGrant"
              ],
              "Resource": "arn:aws:kms:*:451833091580:key/*"
            },
            {
              "Effect": "Allow",
              "Action": [
                "cloudformation:DescribeStacks"
              ],
              "Resource": "arn:aws:cloudformation:*:*:stack/*/*"
            }
          ]
        }
      }
    ],
    "attached_policies": [
      {
        "PolicyName": "LightsailExportAccess",
        "PolicyId": "ANPAJ4LZGPQLZWMVR4WMQ",
        "Arn": "arn:aws:iam::aws:policy/aws-service-role/LightsailExportAccess",
        "Path": "/aws-service-role/",
        "DefaultVersionId": "v2",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "Description": "AWS Lightsail service linked role policy which grants permissions to export resources",
        "CreateDate": "2018-09-28 16:35:54+00:00",
        "UpdateDate": "2022-01-15 01:45:33+00:00",
        "Tags": [],
        "PolicyVersion": {
          "Document": {
            "Version": "2012-10-17",
            "Statement": [
              {
                "Effect": "Allow",
                "Action": [
                  "iam:DeleteServiceLinkedRole",
                  "iam:GetServiceLinkedRoleDeletionStatus"
                ],
                "Resource": "arn:aws:iam::*:role/aws-service-role/lightsail.amazonaws.com/AWSServiceRoleForLightsail*"
              },
              {
                "Effect": "Allow",
                "Action": [
                  "ec2:CopySnapshot",
                  "ec2:DescribeSnapshots",
                  "ec2:CopyImage",
                  "ec2:DescribeImages"
                ],
                "Resource": "*"
              },
              {
                "Effect": "Allow",
                "Action": [
                  "s3:GetAccountPublicAccessBlock"
                ],
                "Resource": "*"
              }
            ]
          },
          "VersionId": "v2",
          "IsDefaultVersion": true,
          "CreateDate": "2022-01-15 01:45:33+00:00"
        }
      }
    ]
  }
]
```
Add `--nl` to collapse these to single lines as valid newline-delimited JSON.

Add `--csv` or `--tsv` to get back CSV or TSV data.

## delete-user

In trying out this tool it's possible you will create several different user accounts that you later decide to clean up.

Deleting AWS users is a little fiddly: you first need to delete their access keys, then their inline policies and finally the user themselves.

The `s3-credentials delete-user` handles this for you:

```bash
s3-credentials delete-user s3.read-write.simonw-test-bucket-10
```
```
User: s3.read-write.simonw-test-bucket-10
  Deleted policy: s3.read-write.simonw-test-bucket-10
  Deleted access key: AKIAWXFXAIOZK3GPEIWR
  Deleted user
```
You can pass it multiple usernames to delete multiple users at a time.

## put-object

You can upload a file to a key in an S3 bucket using `s3-credentials put-object`:
```bash
s3-credentials put-object my-bucket my-key.txt /path/to/file.txt
```
Use `-` as the file name to upload from standard input:
```bash
echo "Hello" | s3-credentials put-object my-bucket hello.txt -
```
This command shows a progress bar by default. Use `-s` or `--silent` to hide the progress bar.

The `Content-Type` on the uploaded object will be automatically set based on the file extension. If you are using standard input, or you want to over-ride the detected type, you can do so using the `--content-type` option:
```bash
echo "<h1>Hello World</h1>" | \
  s3-credentials put-object my-bucket hello.html - --content-type "text/html"
```
## put-objects

`s3-credentials put-objects` can be used to upload more than one file at once.

Pass one or more filenames to upload them to the root of your bucket:
```bash
s3-credentials put-objects my-bucket one.txt two.txt three.txt
```
Use `--prefix my-prefix` to upload them to the specified prefix:
```bash
s3-credentials put-objects my-bucket one.txt --prefix my-prefix
```
This will upload the file to `my-prefix/one.txt`.

Pass one or more directories to upload the contents of those directories.
`.` uploads everything in your current directory:
```bash
s3-credentials put-objects my-bucket .
```
Passing directory names will upload the directory and all of its contents:
```bash
s3-credentials put-objects my-bucket my-directory
```
If `my-directory` had files `one.txt` and `two.txt` in it, the result would be:
```
my-directory/one.txt
my-directory/two.txt
```
A progress bar will be shown by default. Use `-s` or `--silent` to hide it.

Add `--dry-run` to get a preview of what would be uploaded without uploading anything:
```bash
s3-credentials put-objects my-bucket . --dry-run
```
```
out/IMG_1254.jpeg => s3://my-bucket/out/IMG_1254.jpeg
out/alverstone-mead-2.jpg => s3://my-bucket/out/alverstone-mead-2.jpg
out/alverstone-mead-1.jpg => s3://my-bucket/out/alverstone-mead-1.jpg
```

## delete-objects

`s3-credentials delete-objects` can be used to delete one or more keys from the bucket.

Pass one or more keys to delete them:
```bash
s3-credentials delete-objects my-bucket one.txt two.txt three.txt
```
Use `--prefix my-prefix` to delete all keys with the specified prefix:
```bash
s3-credentials delete-objects my-bucket --prefix my-prefix
```
Pass `-d` or `--dry-run` to perform a dry-run of the deletion, which will list the keys that would be deleted without actually deleting them.
```bash
s3-credentials delete-objects my-bucket --prefix my-prefix --dry-run
```
## get-object

To download a file from a bucket use `s3-credentials get-object`:
```bash
s3-credentials get-object my-bucket hello.txt
```
This defaults to outputting the downloaded file to the terminal. You can instead direct it to save to a file on disk using the `-o` or `--output` option:
```bash
s3-credentials get-object my-bucket hello.txt -o /path/to/hello.txt
```
## get-objects

`s3-credentials get-objects` can be used to download multiple files from a bucket at once.

Without extra arguments, this downloads everything:
```bash
s3-credentials get-objects my-bucket
```
Files will be written to the current directory by default, preserving their directory structure from the bucket.

To write to a different directory use `--output` or `-o`:
```bash
s3-credentials get-objects my-bucket -o /path/to/output
```
To download multiple specific files, add them as arguments to the command:
```bash
s3-credentials get-objects my-bucket one.txt two.txt path/to/three.txt
```
You can pass one or more `--pattern` or `-p` options to download files matching a specific pattern:
```bash
s3-credentials get-objects my-bucket -p "*.txt" -p "static/*.css"
```
Here the `*` wildcard will match any sequence of characters, including `/`. `?` will match a single character.

A progress bar will be shown by default. Use `-s` or `--silent` to hide it.

## set-cors-policy and get-cors-policy

You can set the [CORS policy](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html) for a bucket using the `set-cors-policy` command. S3 CORS policies are set at the bucket level - they cannot be set for individual items.

First, create the bucket. Make sure to make it `--public`:
```bash
s3-credentials create my-cors-bucket --public -c
```
You can set a default CORS policy - allowing `GET` requests from any origin - like this:
```bash
s3-credentials set-cors-policy my-cors-bucket
```
You can use the `get-cors-policy` command to confirm the policy you have set:
```bash
s3-credentials get-cors-policy my-cors-bucket
```
```json
[
    {
        "ID": "set-by-s3-credentials",
        "AllowedMethods": [
            "GET"
        ],
        "AllowedOrigins": [
            "*"
        ]
    }
]
```
To customize the CORS policy, use the following options:

- `-m/--allowed-method` - Allowed method e.g. `GET`
- `-h/--allowed-header` - Allowed header e.g. `Authorization`
- `-o/--allowed-origin` - Allowed origin e.g. `https://www.example.com/`
- `-e/--expose-header` -  Header to expose e.g. `ETag`
- `--max-age-seconds` - How long to cache preflight requests

Each of these can be passed multiple times with the exception of `--max-age-seconds`.

The following example allows GET and PUT methods from code running on `https://www.example.com/`, allows the incoming `Authorization` header and exposes the `ETag` header. It also sets the client to cache preflight requests for 60 seconds:
```bash
s3-credentials set-cors-policy my-cors-bucket2 \
  --allowed-method GET \
  --allowed-method PUT \
  --allowed-origin https://www.example.com/ \
  --expose-header ETag \
  --max-age-seconds 60
```
## debug-bucket

The `debug-bucket` command is useful for diagnosing issues with a bucket:
```bash
s3-credentials debug-bucket my-bucket
```
Example output:
```
Bucket ACL:
{
    "Owner": {
        "DisplayName": "username",
        "ID": "cc8ca3a037c6a7c1fa7580076bf7cd1949b3f2f58f01c9df9e53c51f6a249910"
    },
    "Grants": [
        {
            "Grantee": {
                "DisplayName": "username",
                "ID": "cc8ca3a037c6a7c1fa7580076bf7cd1949b3f2f58f01c9df9e53c51f6a249910",
                "Type": "CanonicalUser"
            },
            "Permission": "FULL_CONTROL"
        }
    ]
}
Bucket policy status:
{
    "PolicyStatus": {
        "IsPublic": true
    }
}
Bucket public access block:
{
    "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": false,
        "IgnorePublicAcls": false,
        "BlockPublicPolicy": false,
        "RestrictPublicBuckets": false
    }
}
```
## get-bucket-policy

The `get-bucket-policy` command displays the current bucket policy for a bucket:
```bash
s3-credentials get-bucket-policy my-bucket
```
Example output:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowAllGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*"
        }
    ]
}
```

## set-bucket-policy

The `set-bucket-policy` command can be used to set a bucket policy for a bucket:
```bash
s3-credentials set-bucket-policy my-bucket --policy-file policy.json
```
Or for the common case of setting a policy to allow GET access to all buckets:
```bash
s3-credentials set-bucket-policy my-bucket --allow-all-get
```

## get-public-access-block

The `get-public-access-block` command displays the current public access block configuration for a bucket:
```bash
s3-credentials get-public-access-block my-bucket
```
Example output:

```json
{
    "BlockPublicAcls": false,
    "IgnorePublicAcls": false,
    "BlockPublicPolicy": false,
    "RestrictPublicBuckets": false
}
```

## set-public-access-block

The `set-public-access-block` command can be used to set the public access block configuration for a bucket:
```bash
s3-credentials set-public-access-block my-bucket \
  --block-public-acls true \
  --ignore-public-acls true \
  --block-public-policy true \
  --restrict-public-buckets true
```
Each of the above options accepts `true` or `false`.

You can use the `--allow-public-access` shortcut to set everything to `false` in one go:
```bash
s3-credentials set-public-access-block my-bucket \
  --allow-public-access
```
