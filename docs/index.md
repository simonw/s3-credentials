# s3-credentials

[![PyPI](https://img.shields.io/pypi/v/s3-credentials.svg)](https://pypi.org/project/s3-credentials/)
[![Changelog](https://img.shields.io/github/v/release/simonw/s3-credentials?include_prereleases&label=changelog)](https://github.com/simonw/s3-credentials/releases)
[![Tests](https://github.com/simonw/s3-credentials/workflows/Test/badge.svg)](https://github.com/simonw/s3-credentials/actions?query=workflow%3ATest)
[![Documentation Status](https://readthedocs.org/projects/s3-credentials/badge/?version=latest)](https://s3-credentials.readthedocs.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/simonw/s3-credentials/blob/master/LICENSE)

A tool for creating credentials for accessing S3 buckets

For project background, see [s3-credentials: a tool for creating credentials for S3 buckets](https://simonwillison.net/2021/Nov/3/s3-credentials/) on my blog.

Why would you need this? If you want to read and write to an S3 bucket from an automated script somewhere, you'll need an access key and secret key to authenticate your calls. This tool helps you create those with the most restrictive permissions possible.

If your code is running in EC2 or Lambda you can likely solve this [using roles instead](https://aws.amazon.com/premiumsupport/knowledge-center/lambda-execution-role-s3-bucket/). This tool is mainly useful for when you are interacting with S3 from outside the boundaries of AWS itself.

## Installation

Install this tool using `pip`:

    $ pip install s3-credentials

## Documentation

```{toctree}
---
maxdepth: 3
---
configuration
create
localserver
other-commands
policy-documents
help
contributing
```

## Tips

You can see a log of changes made by this tool using AWS CloudTrail - the following link should provide an Event History interface showing revelant changes made to your AWS account such as `CreateAccessKey`, `CreateUser`, `PutUserPolicy` and more:

<https://console.aws.amazon.com/cloudtrail/home>

You can view a list of your S3 buckets and confirm that they have the desired permissions and properties here:

<https://console.aws.amazon.com/s3/home>

The management interface for an individual bucket is at `https://console.aws.amazon.com/s3/buckets/NAME-OF-BUCKET`
