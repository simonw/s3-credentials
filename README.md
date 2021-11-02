# s3-credentials

[![PyPI](https://img.shields.io/pypi/v/s3-credentials.svg)](https://pypi.org/project/s3-credentials/)
[![Changelog](https://img.shields.io/github/v/release/simonw/s3-credentials?include_prereleases&label=changelog)](https://github.com/simonw/s3-credentials/releases)
[![Tests](https://github.com/simonw/s3-credentials/workflows/Test/badge.svg)](https://github.com/simonw/s3-credentials/actions?query=workflow%3ATest)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/simonw/s3-credentials/blob/master/LICENSE)

NOT YET USABLE.

A tool for creating credentials for accessing S3 buckets

## Installation

Install this tool using `pip`:

    $ pip install s3-credentials

## Usage

To see which user you are authenticated as:

    $ s3-credentials whoami

This will output JSON representing the currently authenticated user.

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
