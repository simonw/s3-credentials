# These integration tests only run with "pytest --integration" -
# they execute live calls against AWS using environment variables
# and clean up after themselves
from click.testing import CliRunner
from s3_credentials.cli import bucket_exists, cli
import botocore
import boto3
import datetime
import json
import pytest
import secrets
import time

# Mark all tests in this module with "integration":
pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def cleanup():
    cleanup_any_resources()
    yield
    cleanup_any_resources()


def test_create_bucket_with_read_write(tmpdir):
    bucket_name = "s3-credentials-tests.read-write.{}".format(secrets.token_hex(4))
    # Bucket should not exist
    s3 = boto3.client("s3")
    assert not bucket_exists(s3, bucket_name)
    credentials = get_output("create", bucket_name, "-c")
    credentials_decoded = json.loads(credentials)
    credentials_s3 = boto3.session.Session(
        aws_access_key_id=credentials_decoded["AccessKeyId"],
        aws_secret_access_key=credentials_decoded["SecretAccessKey"],
    ).client("s3")
    # Bucket should exist - found I needed to sleep(10) before put-object would work
    time.sleep(10)
    assert bucket_exists(s3, bucket_name)
    # Use the credentials to write a file to that bucket
    test_write = tmpdir / "test-write.txt"
    test_write.write_text("hello", "utf-8")
    get_output("put-object", bucket_name, "test-write.txt", str(test_write))
    credentials_s3.put_object(
        Body="hello".encode("utf-8"), Bucket=bucket_name, Key="test-write.txt"
    )
    # Use default s3 client to check that the write succeeded
    get_object_response = s3.get_object(Bucket=bucket_name, Key="test-write.txt")
    assert get_object_response["Body"].read() == b"hello"
    # Check we can read the file using the credentials too
    output = get_output("get-object", bucket_name, "test-write.txt")
    assert output == "hello"


def test_create_bucket_read_only_duration_15():
    bucket_name = "s3-credentials-tests.read-only.{}".format(secrets.token_hex(4))
    s3 = boto3.client("s3")
    assert not bucket_exists(s3, bucket_name)
    credentials_decoded = json.loads(
        get_output("create", bucket_name, "-c", "--duration", "15m", "--read-only")
    )
    assert set(credentials_decoded.keys()) == {
        "AccessKeyId",
        "SecretAccessKey",
        "SessionToken",
        "Expiration",
    }
    # Expiration should be ~15 minutes in the future
    delta = (
        datetime.datetime.fromisoformat(credentials_decoded["Expiration"])
        - datetime.datetime.now(datetime.timezone.utc)
    ).total_seconds()
    # Should be around about 900 seconds
    assert 800 < delta < 1000
    # Wait for everything to exist
    time.sleep(10)
    # Create client with these credentials
    credentials_s3 = boto3.session.Session(
        aws_access_key_id=credentials_decoded["AccessKeyId"],
        aws_secret_access_key=credentials_decoded["SecretAccessKey"],
        aws_session_token=credentials_decoded["SessionToken"],
    ).client("s3")
    # Client should NOT be allowed to write objects
    with pytest.raises(botocore.exceptions.ClientError):
        credentials_s3.put_object(
            Body="hello".encode("utf-8"), Bucket=bucket_name, Key="hello.txt"
        )
    # Write an object using root credentials
    s3.put_object(
        Body="hello read-only".encode("utf-8"),
        Bucket=bucket_name,
        Key="hello-read-only.txt",
    )
    # Client should be able to read this
    credentials_response = credentials_s3.get_object(
        Bucket=bucket_name, Key="hello-read-only.txt"
    )
    assert credentials_response["Body"].read() == b"hello read-only"


def get_output(*args, input=None):
    runner = CliRunner(mix_stderr=False)
    with runner.isolated_filesystem():
        result = runner.invoke(cli, args, catch_exceptions=False, input=input)
    assert result.exit_code == 0, result.stderr
    print(result.stderr)
    return result.stdout


def cleanup_any_resources():
    # Delete any users beginning s3-credentials-tests.
    users = json.loads(get_output("list-users", "--array"))
    users_to_delete = [
        user["UserName"]
        for user in users
        if ".s3-credentials-tests." in user["UserName"]
    ]
    if users_to_delete:
        print("Deleting users: ", users_to_delete)
        get_output("delete-user", *users_to_delete)
    s3 = boto3.client("s3")
    # Delete any buckets beginning s3-credentials-tests.
    buckets = json.loads(get_output("list-buckets", "--array"))
    buckets_to_delete = [
        bucket["Name"]
        for bucket in buckets
        if bucket["Name"].startswith("s3-credentials-tests.")
    ]
    for bucket in buckets_to_delete:
        print("Deleting bucket: {}".format(bucket))
        # Delete all objects in the bucket
        boto3.resource("s3").Bucket(bucket).objects.all().delete()
        # Delete the bucket
        s3.delete_bucket(Bucket=bucket)
