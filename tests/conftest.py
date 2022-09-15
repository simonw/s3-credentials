import boto3
import logging
import os
import pytest
from moto import mock_s3


def pytest_addoption(parser):
    parser.addoption(
        "--integration",
        action="store_true",
        default=False,
        help="run integration tests",
    )
    parser.addoption(
        "--boto-logging",
        action="store_true",
        default=False,
        help="turn on boto3 logging",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "integration: mark test as integration test, only run with --integration",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--boto-logging"):
        boto3.set_stream_logger("botocore.endpoint", logging.DEBUG)
    if config.getoption("--integration"):
        # Also run integration tests
        return
    skip_slow = pytest.mark.skip(reason="use --integration option to run")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_slow)


@pytest.fixture(scope="function")
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="function")
def moto_s3(aws_credentials):
    with mock_s3():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="my-bucket")
        for key in ("one.txt", "directory/two.txt", "directory/three.json"):
            client.put_object(Bucket="my-bucket", Key=key, Body=key.encode("utf-8"))
        yield client
