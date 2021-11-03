import botocore
from click.testing import CliRunner
from s3_credentials.cli import cli
import json
import pytest
from unittest.mock import call, Mock


def test_whoami(mocker):
    boto3 = mocker.patch("boto3.client")
    boto3().get_user.return_value = {"User": {"username": "name"}}
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["whoami"])
        assert result.exit_code == 0
        assert json.loads(result.output) == {"username": "name"}


@pytest.mark.parametrize(
    "option,expected",
    (
        ("", '{\n    "name": "one"\n}\n{\n    "name": "two"\n}\n'),
        (
            "--array",
            '[\n    {\n        "name": "one"\n    },\n'
            '    {\n        "name": "two"\n    }\n]\n',
        ),
        ("--nl", '{"name": "one"}\n{"name": "two"}\n'),
    ),
)
def test_list_users(mocker, option, expected):
    boto3 = mocker.patch("boto3.client")
    boto3().get_paginator().paginate.return_value = [
        {"Users": [{"name": "one"}, {"name": "two"}]}
    ]
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["list-users"] + ([option] if option else []))
        assert result.exit_code == 0
        assert result.output == expected


@pytest.mark.parametrize(
    "option,expected",
    (
        ("", '{\n    "name": "one"\n}\n{\n    "name": "two"\n}\n'),
        (
            "--array",
            '[\n    {\n        "name": "one"\n    },\n'
            '    {\n        "name": "two"\n    }\n]\n',
        ),
        ("--nl", '{"name": "one"}\n{"name": "two"}\n'),
    ),
)
def test_list_buckets(mocker, option, expected):
    boto3 = mocker.patch("boto3.client")
    boto3().list_buckets.return_value = {"Buckets": [{"name": "one"}, {"name": "two"}]}
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["list-buckets"] + ([option] if option else []))
        assert result.exit_code == 0
        assert result.output == expected


CUSTOM_POLICY = '{"custom": "policy", "bucket": "$!BUCKET_NAME!$"}'
READ_WRITE_POLICY = '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1"]}, {"Effect": "Allow", "Action": "s3:*Object", "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1/*"]}]}'
READ_ONLY_POLICY = '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1"]}, {"Effect": "Allow", "Action": "s3:GetObject*", "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1/*"]}]}'
WRITE_ONLY_POLICY = '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1/*"]}]}'


@pytest.mark.parametrize(
    "options,use_policy_stdin,expected_policy,expected_name_fragment",
    (
        ([], False, READ_WRITE_POLICY, "read-write"),
        (["--read-only"], False, READ_ONLY_POLICY, "read-only"),
        (["--write-only"], False, WRITE_ONLY_POLICY, "write-only"),
        (["--policy", "POLICYFILEPATH"], False, CUSTOM_POLICY, "custom"),
        (["--policy", "-"], True, CUSTOM_POLICY, "custom"),
        (["--policy", CUSTOM_POLICY], False, CUSTOM_POLICY, "custom"),
    ),
)
def test_create(
    mocker, tmpdir, options, use_policy_stdin, expected_policy, expected_name_fragment
):
    boto3 = mocker.patch("boto3.client")
    boto3.return_value = Mock()
    boto3.return_value.create_access_key.return_value = {
        "AccessKey": {
            "AccessKeyId": "access",
            "SecretAccessKey": "secret",
        }
    }
    runner = CliRunner()
    with runner.isolated_filesystem():
        filepath = str(tmpdir / "policy.json")
        open(filepath, "w").write(CUSTOM_POLICY)
        fixed_options = [
            filepath if option == "POLICYFILEPATH" else option for option in options
        ]
        args = ["create", "pytest-bucket-simonw-1", "-c"] + fixed_options
        kwargs = {}
        if use_policy_stdin:
            kwargs["input"] = CUSTOM_POLICY
        result = runner.invoke(cli, args, **kwargs)
        assert result.exit_code == 0
        assert result.output == (
            "Attached policy s3.NAME_FRAGMENT.pytest-bucket-simonw-1 to user s3.NAME_FRAGMENT.pytest-bucket-simonw-1\n"
            "Created access key for user: s3.NAME_FRAGMENT.pytest-bucket-simonw-1\n"
            '{\n    "AccessKeyId": "access",\n    "SecretAccessKey": "secret"\n}\n'
        ).replace("NAME_FRAGMENT", expected_name_fragment)
        assert [str(c) for c in boto3.mock_calls] == [
            "call('s3')",
            "call('iam')",
            "call().head_bucket(Bucket='pytest-bucket-simonw-1')",
            "call().get_user(UserName='s3.{}.pytest-bucket-simonw-1')".format(
                expected_name_fragment
            ),
            "call().put_user_policy(PolicyDocument='{}', PolicyName='s3.{}.pytest-bucket-simonw-1', UserName='s3.{}.pytest-bucket-simonw-1')".format(
                expected_policy.replace("$!BUCKET_NAME!$", "pytest-bucket-simonw-1"),
                expected_name_fragment,
                expected_name_fragment,
            ),
            "call().create_access_key(UserName='s3.{}.pytest-bucket-simonw-1')".format(
                expected_name_fragment
            ),
        ]


def test_list_user_policies(mocker):
    boto3 = mocker.patch("boto3.client")
    boto3.return_value = Mock()
    boto3.return_value.get_user_policy.return_value = {
        "PolicyDocument": {"policy": "here"}
    }

    def get_paginator(type):
        m = Mock()
        if type == "list_users":
            m.paginate.return_value = [
                {"Users": [{"UserName": "one"}, {"UserName": "two"}]}
            ]
        elif type == "list_user_policies":
            m.paginate.return_value = [{"PolicyNames": ["policy-one", "policy-two"]}]
        return m

    boto3().get_paginator.side_effect = get_paginator
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["list-user-policies"], catch_exceptions=False)
        assert result.exit_code == 0
        assert result.output == (
            "User: one\n"
            "PolicyName: policy-one\n"
            "{\n"
            '    "policy": "here"\n'
            "}\n"
            "PolicyName: policy-two\n"
            "{\n"
            '    "policy": "here"\n'
            "}\n"
            "User: two\n"
            "PolicyName: policy-one\n"
            "{\n"
            '    "policy": "here"\n'
            "}\n"
            "PolicyName: policy-two\n"
            "{\n"
            '    "policy": "here"\n'
            "}\n"
        )
        assert boto3.mock_calls == [
            call(),
            call("iam"),
            call().get_paginator("list_users"),
            call().get_paginator("list_user_policies"),
            call().get_user_policy(UserName="one", PolicyName="policy-one"),
            call().get_user_policy(UserName="one", PolicyName="policy-two"),
            call().get_user_policy(UserName="two", PolicyName="policy-one"),
            call().get_user_policy(UserName="two", PolicyName="policy-two"),
        ]


def test_delete_user(mocker):
    boto3 = mocker.patch("boto3.client")
    boto3.return_value = Mock()
    boto3.return_value.get_user_policy.return_value = {
        "PolicyDocument": {"policy": "here"}
    }

    def get_paginator(type):
        m = Mock()
        if type == "list_access_keys":
            m.paginate.return_value = [
                {"AccessKeyMetadata": [{"AccessKeyId": "one"}, {"AccessKeyId": "two"}]}
            ]
        elif type == "list_user_policies":
            m.paginate.return_value = [{"PolicyNames": ["policy-one"]}]
        return m

    boto3().get_paginator.side_effect = get_paginator
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["delete-user", "user-123"], catch_exceptions=False)
        assert result.exit_code == 0
        assert result.output == (
            "User: user-123\n"
            "  Deleted policy: policy-one\n"
            "  Deleted access key: one\n"
            "  Deleted access key: two\n"
            "  Deleted user\n"
        )
        assert boto3.mock_calls == [
            call(),
            call("iam"),
            call().get_paginator("list_user_policies"),
            call().get_paginator("list_access_keys"),
            call().delete_user_policy(UserName="user-123", PolicyName="policy-one"),
            call().delete_access_key(UserName="user-123", AccessKeyId="one"),
            call().delete_access_key(UserName="user-123", AccessKeyId="two"),
            call().delete_user(UserName="user-123"),
        ]


@pytest.mark.parametrize(
    "strategy,expected_error",
    (
        ("stdin", "Input contained invalid JSON"),
        ("filepath", "File contained invalid JSON"),
        ("string", "Invalid JSON string"),
    ),
)
@pytest.mark.parametrize("use_valid_string", (True, False))
def test_verify_create_policy_option(
    tmpdir, mocker, strategy, expected_error, use_valid_string
):
    # Ensure "bucket does not exist" error to terminate after verification
    boto3 = mocker.patch("boto3.client")
    boto3.return_value.head_bucket.side_effect = botocore.exceptions.ClientError(
        error_response={}, operation_name=""
    )
    if use_valid_string:
        content = '{"policy": "..."}'
    else:
        content = "{Invalid JSON"
    # Only used by strategy==filepath
    filepath = str(tmpdir / "policy.json")
    open(filepath, "w").write(content)

    runner = CliRunner()
    args = ["create", "my-bucket", "--policy"]
    kwargs = {}
    if strategy == "stdin":
        args.append("-")
        kwargs["input"] = content
    elif strategy == "filepath":
        args.append(filepath)
    elif strategy == "string":
        args.append(content)

    result = runner.invoke(cli, args, **kwargs)
    if use_valid_string:
        assert result.exit_code == 1
        assert (
            result.output
            == "Error: Bucket does not exist: my-bucket - try --create-bucket to create it\n"
        )
    else:
        assert result.exit_code
        assert (
            "Error: Invalid value for '--policy': {}".format(expected_error)
            in result.output
        )
