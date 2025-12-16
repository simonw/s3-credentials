"""Tests for the localserver command and related functionality."""

import botocore
from click.testing import CliRunner
from s3_credentials.cli import cli
import datetime
import json
import pytest
from unittest.mock import Mock


def test_localserver_missing_duration():
    runner = CliRunner()
    result = runner.invoke(cli, ["localserver", "my-bucket"])
    assert result.exit_code == 2
    assert "Missing option" in result.output
    assert "duration" in result.output.lower()


def test_localserver_invalid_duration():
    runner = CliRunner()
    result = runner.invoke(cli, ["localserver", "my-bucket", "--duration", "5s"])
    assert result.exit_code == 2
    assert "Duration must be between 15 minutes and 12 hours" in result.output


def test_localserver_read_only_write_only_conflict():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "localserver",
            "my-bucket",
            "--duration",
            "15m",
            "--read-only",
            "--write-only",
        ],
    )
    assert result.exit_code == 1
    assert "Cannot use --read-only and --write-only at the same time" in result.output


def test_localserver_bucket_not_exists(mocker):
    boto3 = mocker.patch("boto3.client")
    boto3.return_value = Mock()
    boto3.return_value.head_bucket.side_effect = botocore.exceptions.ClientError(
        error_response={}, operation_name=""
    )

    runner = CliRunner()
    result = runner.invoke(
        cli, ["localserver", "nonexistent-bucket", "--duration", "15m"]
    )
    assert result.exit_code == 1
    assert "Bucket does not exist: nonexistent-bucket" in result.output


def test_credential_cache_generates_credentials(mocker):
    from s3_credentials.localserver import CredentialCache

    mock_iam = Mock()
    mock_sts = Mock()

    mock_sts.get_caller_identity.return_value = {"Account": "123456"}
    mock_iam.get_role.return_value = {"Role": {"Arn": "arn:aws:iam::123456:role/test"}}
    mock_sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "SessionToken": "session-token",
            "Expiration": datetime.datetime(2025, 12, 16, 12, 0, 0),
        }
    }

    cache = CredentialCache(
        iam=mock_iam,
        sts=mock_sts,
        bucket="test-bucket",
        permission="read-only",
        prefix="*",
        duration=900,  # 15 minutes
        extra_statements=[],
    )

    credentials = cache.get_credentials()

    assert credentials["AccessKeyId"] == "AKIAIOSFODNN7EXAMPLE"
    assert credentials["SecretAccessKey"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert credentials["SessionToken"] == "session-token"

    mock_sts.assume_role.assert_called_once()
    call_kwargs = mock_sts.assume_role.call_args[1]
    assert call_kwargs["RoleArn"] == "arn:aws:iam::123456:role/test"
    assert call_kwargs["RoleSessionName"] == "s3.read-only.test-bucket"
    assert call_kwargs["DurationSeconds"] == 900


def test_credential_cache_caches_credentials(mocker):
    from s3_credentials.localserver import CredentialCache

    mock_iam = Mock()
    mock_sts = Mock()

    mock_sts.get_caller_identity.return_value = {"Account": "123456"}
    mock_iam.get_role.return_value = {"Role": {"Arn": "arn:aws:iam::123456:role/test"}}
    mock_sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
            "Expiration": datetime.datetime(2025, 12, 16, 12, 0, 0),
        }
    }

    cache = CredentialCache(
        iam=mock_iam,
        sts=mock_sts,
        bucket="test-bucket",
        permission="read-write",
        prefix="*",
        duration=900,
        extra_statements=[],
    )

    # Get credentials twice
    creds1 = cache.get_credentials()
    creds2 = cache.get_credentials()

    # Should be the same object (cached)
    assert creds1 is creds2
    # Should only have called assume_role once
    assert mock_sts.assume_role.call_count == 1


def test_credential_cache_refreshes_after_duration(mocker):
    from s3_credentials.localserver import CredentialCache
    import time

    mock_iam = Mock()
    mock_sts = Mock()

    mock_sts.get_caller_identity.return_value = {"Account": "123456"}
    mock_iam.get_role.return_value = {"Role": {"Arn": "arn:aws:iam::123456:role/test"}}
    mock_sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
            "Expiration": datetime.datetime(2025, 12, 16, 12, 0, 0),
        }
    }

    cache = CredentialCache(
        iam=mock_iam,
        sts=mock_sts,
        bucket="test-bucket",
        permission="read-write",
        prefix="*",
        duration=1,  # 1 second for testing
        extra_statements=[],
    )

    # Get credentials first time
    cache.get_credentials()
    assert mock_sts.assume_role.call_count == 1

    # Wait for duration to expire
    time.sleep(1.1)

    # Get credentials again - should regenerate
    cache.get_credentials()
    assert mock_sts.assume_role.call_count == 2


@pytest.mark.parametrize(
    "permission,expected_permission",
    (
        ("read-write", "read-write"),
        ("read-only", "read-only"),
        ("write-only", "write-only"),
    ),
)
def test_credential_cache_permission_in_session_name(
    mocker, permission, expected_permission
):
    from s3_credentials.localserver import CredentialCache

    mock_iam = Mock()
    mock_sts = Mock()

    mock_sts.get_caller_identity.return_value = {"Account": "123456"}
    mock_iam.get_role.return_value = {"Role": {"Arn": "arn:aws:iam::123456:role/test"}}
    mock_sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
            "Expiration": datetime.datetime(2025, 12, 16, 12, 0, 0),
        }
    }

    cache = CredentialCache(
        iam=mock_iam,
        sts=mock_sts,
        bucket="my-bucket",
        permission=permission,
        prefix="*",
        duration=900,
        extra_statements=[],
    )

    cache.get_credentials()

    call_kwargs = mock_sts.assume_role.call_args[1]
    assert call_kwargs["RoleSessionName"] == f"s3.{expected_permission}.my-bucket"


def test_credential_cache_policy_generation(mocker):
    from s3_credentials.localserver import CredentialCache

    mock_iam = Mock()
    mock_sts = Mock()

    mock_sts.get_caller_identity.return_value = {"Account": "123456"}
    mock_iam.get_role.return_value = {"Role": {"Arn": "arn:aws:iam::123456:role/test"}}
    mock_sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
            "Expiration": datetime.datetime(2025, 12, 16, 12, 0, 0),
        }
    }

    cache = CredentialCache(
        iam=mock_iam,
        sts=mock_sts,
        bucket="test-bucket",
        permission="read-only",
        prefix="*",
        duration=900,
        extra_statements=[],
    )

    cache.get_credentials()

    call_kwargs = mock_sts.assume_role.call_args[1]
    policy = json.loads(call_kwargs["Policy"])
    assert policy["Version"] == "2012-10-17"
    assert len(policy["Statement"]) == 2
    # Should have ListBucket and GetObject statements
    actions = []
    for stmt in policy["Statement"]:
        actions.extend(stmt["Action"])
    assert "s3:ListBucket" in actions
    assert "s3:GetObject" in actions


def test_make_credential_handler_returns_credentials(mocker):
    from s3_credentials.localserver import make_credential_handler
    import io

    mock_cache = Mock()
    mock_cache.get_credentials.return_value = {
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "SessionToken": "session-token",
        "Expiration": datetime.datetime(2025, 12, 16, 12, 0, 0),
    }

    handler_class = make_credential_handler(mock_cache)

    # Create handler instance with mocked internals
    handler = handler_class.__new__(handler_class)
    handler.path = "/"
    handler.wfile = io.BytesIO()
    handler.request_version = "HTTP/1.1"
    handler.requestline = "GET / HTTP/1.1"

    # Mock response methods
    response_code = None
    headers = {}

    def mock_send_response(code):
        nonlocal response_code
        response_code = code

    def mock_send_header(name, value):
        headers[name] = value

    def mock_end_headers():
        pass

    handler.send_response = mock_send_response
    handler.send_header = mock_send_header
    handler.end_headers = mock_end_headers

    # Call do_GET
    handler.do_GET()

    # Verify response
    assert response_code == 200
    assert headers["Content-Type"] == "application/json"

    # Parse the response body
    response_body = handler.wfile.getvalue().decode()
    response_json = json.loads(response_body)
    assert response_json["Version"] == 1
    assert response_json["AccessKeyId"] == "AKIAIOSFODNN7EXAMPLE"
    assert (
        response_json["SecretAccessKey"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )
    assert response_json["SessionToken"] == "session-token"


def test_make_credential_handler_404_on_wrong_path(mocker):
    from s3_credentials.localserver import make_credential_handler
    import io

    mock_cache = Mock()
    handler_class = make_credential_handler(mock_cache)

    handler = handler_class.__new__(handler_class)
    handler.path = "/wrong-path"
    handler.wfile = io.BytesIO()
    handler.request_version = "HTTP/1.1"

    response_code = None
    headers = {}

    def mock_send_response(code):
        nonlocal response_code
        response_code = code

    handler.send_response = mock_send_response
    handler.send_header = lambda name, value: headers.update({name: value})
    handler.end_headers = lambda: None

    handler.do_GET()

    assert response_code == 404
    response_body = handler.wfile.getvalue().decode()
    assert "Not found" in response_body


def test_make_credential_handler_500_on_error(mocker):
    from s3_credentials.localserver import make_credential_handler
    import io

    mock_cache = Mock()
    mock_cache.get_credentials.side_effect = Exception("AWS Error")

    handler_class = make_credential_handler(mock_cache)

    handler = handler_class.__new__(handler_class)
    handler.path = "/"
    handler.wfile = io.BytesIO()
    handler.request_version = "HTTP/1.1"

    response_code = None

    def mock_send_response(code):
        nonlocal response_code
        response_code = code

    handler.send_response = mock_send_response
    handler.send_header = lambda name, value: None
    handler.end_headers = lambda: None

    handler.do_GET()

    assert response_code == 500
    response_body = handler.wfile.getvalue().decode()
    assert "AWS Error" in response_body
