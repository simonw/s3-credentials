import botocore
from click.testing import CliRunner
import s3_credentials
from s3_credentials.cli import cli
import json
import os
import pathlib
import pytest
from unittest.mock import call, Mock
from botocore.stub import Stubber


@pytest.fixture
def stub_iam(mocker):
    client = botocore.session.get_session().create_client("iam")
    stubber = Stubber(client)
    stubber.activate()
    mocker.patch("s3_credentials.cli.make_client", return_value=client)
    return stubber


@pytest.fixture
def stub_s3(mocker):
    client = botocore.session.get_session().create_client("s3")
    stubber = Stubber(client)
    stubber.activate()
    mocker.patch("s3_credentials.cli.make_client", return_value=client)
    return stubber


@pytest.fixture
def stub_sts(mocker):
    client = botocore.session.get_session().create_client("sts")
    stubber = Stubber(client)
    stubber.activate()
    mocker.patch("s3_credentials.cli.make_client", return_value=client)
    return stubber


def test_whoami(mocker, stub_sts):
    stub_sts.add_response(
        "get_caller_identity",
        {
            "UserId": "AEONAUTHOUNTOHU",
            "Account": "123456",
            "Arn": "arn:aws:iam::123456:user/user-name",
            "ResponseMetadata": {},
        },
    )

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["whoami"])
        assert result.exit_code == 0
        assert json.loads(result.output) == {
            "UserId": "AEONAUTHOUNTOHU",
            "Account": "123456",
            "Arn": "arn:aws:iam::123456:user/user-name",
        }


@pytest.mark.parametrize(
    "option,expected",
    (
        (
            "",
            "[\n"
            "  {\n"
            '    "Path": "/",\n'
            '    "UserName": "NameA",\n'
            '    "UserId": "AID000000000000000001",\n'
            '    "Arn": "arn:aws:iam::000000000000:user/NameB",\n'
            '    "CreateDate": "2020-01-01 00:00:00+00:00"\n'
            "  },\n"
            "  {\n"
            '    "Path": "/",\n'
            '    "UserName": "NameA",\n'
            '    "UserId": "AID000000000000000000",\n'
            '    "Arn": "arn:aws:iam::000000000000:user/NameB",\n'
            '    "CreateDate": "2020-01-01 00:00:00+00:00"\n'
            "  }\n"
            "]\n",
        ),
        (
            "--nl",
            '{"Path": "/", "UserName": "NameA", "UserId": "AID000000000000000001", "Arn": "arn:aws:iam::000000000000:user/NameB", "CreateDate": "2020-01-01 00:00:00+00:00"}\n'
            '{"Path": "/", "UserName": "NameA", "UserId": "AID000000000000000000", "Arn": "arn:aws:iam::000000000000:user/NameB", "CreateDate": "2020-01-01 00:00:00+00:00"}\n',
        ),
        (
            "--csv",
            (
                "UserName,UserId,Arn,Path,CreateDate,PasswordLastUsed,PermissionsBoundary,Tags\n"
                "NameA,AID000000000000000001,arn:aws:iam::000000000000:user/NameB,/,2020-01-01 00:00:00+00:00,,,\n"
                "NameA,AID000000000000000000,arn:aws:iam::000000000000:user/NameB,/,2020-01-01 00:00:00+00:00,,,\n"
            ),
        ),
        (
            "--tsv",
            (
                "UserName\tUserId\tArn\tPath\tCreateDate\tPasswordLastUsed\tPermissionsBoundary\tTags\n"
                "NameA\tAID000000000000000001\tarn:aws:iam::000000000000:user/NameB\t/\t2020-01-01 00:00:00+00:00\t\t\t\n"
                "NameA\tAID000000000000000000\tarn:aws:iam::000000000000:user/NameB\t/\t2020-01-01 00:00:00+00:00\t\t\t\n"
            ),
        ),
    ),
)
def test_list_users(option, expected, stub_iam):
    stub_iam.add_response(
        "list_users",
        {
            "Users": [
                {
                    "Path": "/",
                    "UserName": "NameA",
                    "UserId": "AID000000000000000001",
                    "Arn": "arn:aws:iam::000000000000:user/NameB",
                    "CreateDate": "2020-01-01 00:00:00+00:00",
                },
                {
                    "Path": "/",
                    "UserName": "NameA",
                    "UserId": "AID000000000000000000",
                    "Arn": "arn:aws:iam::000000000000:user/NameB",
                    "CreateDate": "2020-01-01 00:00:00+00:00",
                },
            ]
        },
    )

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["list-users"] + ([option] if option else []))
        assert result.exit_code == 0
        assert result.output == expected


@pytest.mark.parametrize(
    "options,expected",
    (
        (
            [],
            (
                "[\n"
                "  {\n"
                '    "Name": "bucket-one",\n'
                '    "CreationDate": "2020-01-01 00:00:00+00:00"\n'
                "  },\n"
                "  {\n"
                '    "Name": "bucket-two",\n'
                '    "CreationDate": "2020-02-01 00:00:00+00:00"\n'
                "  }\n"
                "]\n"
            ),
        ),
        (
            ["--nl"],
            '{"Name": "bucket-one", "CreationDate": "2020-01-01 00:00:00+00:00"}\n'
            '{"Name": "bucket-two", "CreationDate": "2020-02-01 00:00:00+00:00"}\n',
        ),
        (
            ["--nl", "bucket-one"],
            '{"Name": "bucket-one", "CreationDate": "2020-01-01 00:00:00+00:00"}\n',
        ),
    ),
)
def test_list_buckets(stub_s3, options, expected):
    stub_s3.add_response(
        "list_buckets",
        {
            "Buckets": [
                {
                    "Name": "bucket-one",
                    "CreationDate": "2020-01-01 00:00:00+00:00",
                },
                {
                    "Name": "bucket-two",
                    "CreationDate": "2020-02-01 00:00:00+00:00",
                },
            ]
        },
    )
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["list-buckets"] + options)
        assert result.exit_code == 0
        assert result.output == expected


def test_list_buckets_details(stub_s3):
    stub_s3.add_response(
        "list_buckets",
        {
            "Buckets": [
                {
                    "Name": "bucket-one",
                    "CreationDate": "2020-01-01 00:00:00+00:00",
                }
            ]
        },
    )
    stub_s3.add_response(
        "get_bucket_acl",
        {
            "Owner": {
                "DisplayName": "swillison",
                "ID": "36b2eeee501c5952a8ac119f9e5212277a4c01eccfa8d6a9d670bba1e2d5f441",
            },
            "Grants": [
                {
                    "Grantee": {
                        "DisplayName": "swillison",
                        "ID": "36b2eeee501c5952a8ac119f9e5212277a4c01eccfa8d6a9d670bba1e2d5f441",
                        "Type": "CanonicalUser",
                    },
                    "Permission": "FULL_CONTROL",
                }
            ],
            "ResponseMetadata": {},
        },
    )
    stub_s3.add_response(
        "get_bucket_location",
        {
            "LocationConstraint": "us-west-2",
        },
    )
    stub_s3.add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        },
    )
    stub_s3.add_response(
        "get_bucket_website",
        {
            "IndexDocument": {"Suffix": "index.html"},
            "ErrorDocument": {"Key": "error.html"},
        },
    )
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["list-buckets", "--details"])
        assert result.exit_code == 0
        assert result.output == (
            "[\n"
            "  {\n"
            '    "Name": "bucket-one",\n'
            '    "CreationDate": "2020-01-01 00:00:00+00:00",\n'
            '    "region": "us-west-2",\n'
            '    "bucket_acl": {\n'
            '      "Owner": {\n'
            '        "DisplayName": "swillison",\n'
            '        "ID": "36b2eeee501c5952a8ac119f9e5212277a4c01eccfa8d6a9d670bba1e2d5f441"\n'
            "      },\n"
            '      "Grants": [\n'
            "        {\n"
            '          "Grantee": {\n'
            '            "DisplayName": "swillison",\n'
            '            "ID": "36b2eeee501c5952a8ac119f9e5212277a4c01eccfa8d6a9d670bba1e2d5f441",\n'
            '            "Type": "CanonicalUser"\n'
            "          },\n"
            '          "Permission": "FULL_CONTROL"\n'
            "        }\n"
            "      ]\n"
            "    },\n"
            '    "public_access_block": {\n'
            '      "BlockPublicAcls": true,\n'
            '      "IgnorePublicAcls": true,\n'
            '      "BlockPublicPolicy": true,\n'
            '      "RestrictPublicBuckets": true\n'
            "    },\n"
            '    "bucket_website": {\n'
            '      "IndexDocument": {\n'
            '        "Suffix": "index.html"\n'
            "      },\n"
            '      "ErrorDocument": {\n'
            '        "Key": "error.html"\n'
            "      },\n"
            '      "url": "http://bucket-one.s3-website.us-west-2.amazonaws.com/"\n'
            "    }\n"
            "  }\n"
            "]\n"
        )


CUSTOM_POLICY = '{"custom": "policy", "bucket": "$!BUCKET_NAME!$"}'
READ_WRITE_POLICY = '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1"]}, {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectAcl", "s3:GetObjectLegalHold", "s3:GetObjectRetention", "s3:GetObjectTagging"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1/*"]}, {"Effect": "Allow", "Action": ["s3:PutObject", "s3:DeleteObject"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1/*"]}]}'
READ_ONLY_POLICY = '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1"]}, {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectAcl", "s3:GetObjectLegalHold", "s3:GetObjectRetention", "s3:GetObjectTagging"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1/*"]}]}'
WRITE_ONLY_POLICY = '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1/*"]}]}'
PREFIX_POLICY = '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetBucketLocation"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1"]}, {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1"], "Condition": {"StringLike": {"s3:prefix": ["my-prefix/*"]}}}, {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectAcl", "s3:GetObjectLegalHold", "s3:GetObjectRetention", "s3:GetObjectTagging"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1/my-prefix/*"]}, {"Effect": "Allow", "Action": ["s3:PutObject", "s3:DeleteObject"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1/my-prefix/*"]}]}'
EXTRA_STATEMENTS_POLICY = '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1"]}, {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectAcl", "s3:GetObjectLegalHold", "s3:GetObjectRetention", "s3:GetObjectTagging"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1/*"]}, {"Effect": "Allow", "Action": ["s3:PutObject", "s3:DeleteObject"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1/*"]}, {"Effect": "Allow", "Action": "textract:*", "Resource": "*"}]}'

# Used by both test_create and test_create_duration
CREATE_TESTS = (
    # options,use_policy_stdin,expected_policy,expected_name_fragment
    ([], False, READ_WRITE_POLICY, "read-write"),
    (["--read-only"], False, READ_ONLY_POLICY, "read-only"),
    (["--write-only"], False, WRITE_ONLY_POLICY, "write-only"),
    (["--prefix", "my-prefix/"], False, PREFIX_POLICY, "read-write"),
    (["--policy", "POLICYFILEPATH"], False, CUSTOM_POLICY, "custom"),
    (["--policy", "-"], True, CUSTOM_POLICY, "custom"),
    (["--policy", CUSTOM_POLICY], False, CUSTOM_POLICY, "custom"),
    (
        ["--statement", '{"Effect": "Allow", "Action": "textract:*", "Resource": "*"}'],
        False,
        EXTRA_STATEMENTS_POLICY,
        "custom",
    ),
)


@pytest.mark.parametrize(
    "options,use_policy_stdin,expected_policy,expected_name_fragment",
    CREATE_TESTS,
)
def test_create(
    mocker, tmpdir, options, use_policy_stdin, expected_policy, expected_name_fragment
):
    boto3 = mocker.patch("boto3.client")
    boto3.return_value = Mock()
    boto3.return_value.create_access_key.return_value = {
        "AccessKey": {"AccessKeyId": "access", "SecretAccessKey": "secret"}
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
        result = runner.invoke(cli, args, **kwargs, catch_exceptions=False)
        assert result.exit_code == 0
        assert result.output == (
            "Attached policy s3.NAME_FRAGMENT.pytest-bucket-simonw-1 to user s3.NAME_FRAGMENT.pytest-bucket-simonw-1\n"
            "Created access key for user: s3.NAME_FRAGMENT.pytest-bucket-simonw-1\n"
            '{\n    "AccessKeyId": "access",\n    "SecretAccessKey": "secret"\n}\n'
        ).replace("NAME_FRAGMENT", expected_name_fragment)
        assert [str(c) for c in boto3.mock_calls] == [
            "call('s3')",
            "call('iam')",
            "call('sts')",
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


@pytest.mark.parametrize(
    "statement,expected_error",
    (
        ("", "Invalid JSON string"),
        ("{}", "missing required keys: Action, Effect, Resource"),
        ('{"Action": 1}', "missing required keys: Effect, Resource"),
        ('{"Action": 1, "Effect": 2}', "missing required keys: Resource"),
    ),
)
def test_create_statement_error(statement, expected_error):
    runner = CliRunner()
    result = runner.invoke(cli, ["create", "--statement", statement])
    assert result.exit_code == 2
    assert expected_error in result.output


@pytest.fixture
def mocked_for_duration(mocker):
    boto3 = mocker.patch("boto3.client")
    boto3.return_value = Mock()
    boto3.return_value.create_access_key.return_value = {
        "AccessKey": {"AccessKeyId": "access", "SecretAccessKey": "secret"}
    }
    boto3.return_value.get_caller_identity.return_value = {"Account": "1234"}
    boto3.return_value.get_role.return_value = {"Role": {"Arn": "arn:::role"}}
    boto3.return_value.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "access",
            "SecretAccessKey": "secret",
            "SessionToken": "session",
        }
    }
    return boto3


@pytest.mark.parametrize(
    "options,use_policy_stdin,expected_policy,expected_name_fragment",
    CREATE_TESTS,
)
def test_create_duration(
    mocked_for_duration,
    tmpdir,
    options,
    use_policy_stdin,
    expected_policy,
    expected_name_fragment,
):
    runner = CliRunner()
    with runner.isolated_filesystem():
        filepath = str(tmpdir / "policy.json")
        open(filepath, "w").write(CUSTOM_POLICY)
        fixed_options = [
            filepath if option == "POLICYFILEPATH" else option for option in options
        ]
        args = [
            "create",
            "pytest-bucket-simonw-1",
            "-c",
            "--duration",
            "15m",
        ] + fixed_options
        kwargs = {}
        if use_policy_stdin:
            kwargs["input"] = CUSTOM_POLICY
        result = runner.invoke(cli, args, **kwargs, catch_exceptions=False)
        assert result.exit_code == 0
        assert result.output == (
            "Assume role against arn:::role for 900s\n"
            "{\n"
            '    "AccessKeyId": "access",\n'
            '    "SecretAccessKey": "secret",\n'
            '    "SessionToken": "session"\n'
            "}\n"
        )
        assert mocked_for_duration.mock_calls == [
            call("s3"),
            call("iam"),
            call("sts"),
            call().head_bucket(Bucket="pytest-bucket-simonw-1"),
            call().get_caller_identity(),
            call().get_role(RoleName="s3-credentials.AmazonS3FullAccess"),
            call().assume_role(
                RoleArn="arn:::role",
                RoleSessionName="s3.{fragment}.pytest-bucket-simonw-1".format(
                    fragment=expected_name_fragment
                ),
                Policy="{policy}".format(
                    policy=expected_policy.replace(
                        "$!BUCKET_NAME!$", "pytest-bucket-simonw-1"
                    ),
                ),
                DurationSeconds=900,
            ),
        ]


def test_create_public(mocker):
    boto3 = mocker.patch("boto3.client")
    boto3.return_value = Mock()
    boto3.return_value.create_access_key.return_value = {
        "AccessKey": {"AccessKeyId": "access", "SecretAccessKey": "secret"}
    }
    # Fake that the bucket does not exist
    boto3.return_value.head_bucket.side_effect = botocore.exceptions.ClientError(
        error_response={}, operation_name=""
    )
    runner = CliRunner()
    with runner.isolated_filesystem():
        args = ["create", "pytest-bucket-simonw-1", "-c", "--public"]
        result = runner.invoke(cli, args, catch_exceptions=False)
        assert result.exit_code == 0
        assert result.output == (
            "Created bucket: pytest-bucket-simonw-1\n"
            "Set public access block configuration\n"
            "Attached bucket policy allowing public access\n"
            "Attached policy s3.read-write.pytest-bucket-simonw-1 to user s3.read-write.pytest-bucket-simonw-1\n"
            "Created access key for user: s3.read-write.pytest-bucket-simonw-1\n"
            "{\n"
            '    "AccessKeyId": "access",\n'
            '    "SecretAccessKey": "secret"\n'
            "}\n"
        )
        assert [str(c) for c in boto3.mock_calls] == [
            "call('s3')",
            "call('iam')",
            "call('sts')",
            "call().head_bucket(Bucket='pytest-bucket-simonw-1')",
            "call().create_bucket(Bucket='pytest-bucket-simonw-1')",
            "call().put_public_access_block(Bucket='pytest-bucket-simonw-1', PublicAccessBlockConfiguration={'BlockPublicAcls': False, 'IgnorePublicAcls': False, 'BlockPublicPolicy': False, 'RestrictPublicBuckets': False})",
            'call().put_bucket_policy(Bucket=\'pytest-bucket-simonw-1\', Policy=\'{"Version": "2012-10-17", "Statement": [{"Sid": "AllowAllGetObject", "Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1/*"]}]}\')',
            "call().get_user(UserName='s3.read-write.pytest-bucket-simonw-1')",
            "call().put_user_policy(PolicyDocument='{}', PolicyName='s3.read-write.pytest-bucket-simonw-1', UserName='s3.read-write.pytest-bucket-simonw-1')".format(
                READ_WRITE_POLICY.replace("$!BUCKET_NAME!$", "pytest-bucket-simonw-1"),
            ),
            "call().create_access_key(UserName='s3.read-write.pytest-bucket-simonw-1')",
        ]


def test_create_website(mocker):
    boto3 = mocker.patch("boto3.client")
    boto3.return_value = Mock()
    boto3.return_value.create_access_key.return_value = {
        "AccessKey": {"AccessKeyId": "access", "SecretAccessKey": "secret"}
    }
    # Fake that the bucket does not exist
    boto3.return_value.head_bucket.side_effect = botocore.exceptions.ClientError(
        error_response={}, operation_name=""
    )
    runner = CliRunner()
    with runner.isolated_filesystem():
        args = ["create", "pytest-bucket-simonw-1", "-c", "--website"]
        result = runner.invoke(cli, args, catch_exceptions=False)
        assert result.exit_code == 0
        assert result.output == (
            "Created bucket: pytest-bucket-simonw-1\n"
            "Set public access block configuration\n"
            "Attached bucket policy allowing public access\n"
            "Configured website: IndexDocument=index.html, ErrorDocument=error.html\n"
            "Attached policy s3.read-write.pytest-bucket-simonw-1 to user s3.read-write.pytest-bucket-simonw-1\n"
            "Created access key for user: s3.read-write.pytest-bucket-simonw-1\n"
            "{\n"
            '    "AccessKeyId": "access",\n'
            '    "SecretAccessKey": "secret"\n'
            "}\n"
        )
        assert [str(c) for c in boto3.mock_calls] == [
            "call('s3')",
            "call('iam')",
            "call('sts')",
            "call().head_bucket(Bucket='pytest-bucket-simonw-1')",
            "call().create_bucket(Bucket='pytest-bucket-simonw-1')",
            "call().put_public_access_block(Bucket='pytest-bucket-simonw-1', PublicAccessBlockConfiguration={'BlockPublicAcls': False, 'IgnorePublicAcls': False, 'BlockPublicPolicy': False, 'RestrictPublicBuckets': False})",
            'call().put_bucket_policy(Bucket=\'pytest-bucket-simonw-1\', Policy=\'{"Version": "2012-10-17", "Statement": [{"Sid": "AllowAllGetObject", "Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::pytest-bucket-simonw-1/*"]}]}\')',
            "call().put_bucket_website(Bucket='pytest-bucket-simonw-1', WebsiteConfiguration={'ErrorDocument': {'Key': 'error.html'}, 'IndexDocument': {'Suffix': 'index.html'}})",
            "call().get_user(UserName='s3.read-write.pytest-bucket-simonw-1')",
            "call().put_user_policy(PolicyDocument='{}', PolicyName='s3.read-write.pytest-bucket-simonw-1', UserName='s3.read-write.pytest-bucket-simonw-1')".format(
                READ_WRITE_POLICY.replace("$!BUCKET_NAME!$", "pytest-bucket-simonw-1"),
            ),
            "call().create_access_key(UserName='s3.read-write.pytest-bucket-simonw-1')",
        ]


def test_create_format_ini(mocker):
    boto3 = mocker.patch("boto3.client")
    boto3.return_value = Mock()
    boto3.return_value.create_access_key.return_value = {
        "AccessKey": {
            "AccessKeyId": "access",
            "SecretAccessKey": "secret",
            "SessionToken": "session",
        }
    }
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["create", "test-bucket", "-c", "-f", "ini"],
    )
    assert result.exit_code == 0
    assert (
        "[default]\naws_access_key_id=access\naws_secret_access_key=secret\n"
        in result.output
    )


def test_create_format_duration_ini(mocked_for_duration):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["create", "test-bucket", "-c", "--duration", "15m", "-f", "ini"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert (
        "[default]\n"
        "aws_access_key_id=access\n"
        "aws_secret_access_key=secret\n"
        "aws_session_token=session\n"
    ) in result.output


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
            call().get_paginator("list_user_policies"),
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
            call().delete_user_policy(UserName="user-123", PolicyName="policy-one"),
            call().get_paginator("list_access_keys"),
            call().delete_access_key(UserName="user-123", AccessKeyId="one"),
            call().delete_access_key(UserName="user-123", AccessKeyId="two"),
            call().delete_user(UserName="user-123"),
        ]


def test_get_cors_policy(mocker):
    boto3 = mocker.patch("boto3.client")
    boto3.return_value = Mock()
    boto3.return_value.get_bucket_cors.return_value = {
        "CORSRules": [
            {
                "ID": "set-by-s3-credentials",
                "AllowedMethods": ["GET"],
                "AllowedOrigins": ["*"],
            }
        ]
    }
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            cli, ["get-cors-policy", "my-bucket"], catch_exceptions=False
        )
        assert result.exit_code == 0
        assert result.output == (
            "["
            "\n    {"
            '\n        "ID": "set-by-s3-credentials",'
            '\n        "AllowedMethods": ['
            '\n            "GET"'
            "\n        ],"
            '\n        "AllowedOrigins": ['
            '\n            "*"'
            "\n        ]"
            "\n    }"
            "\n]\n"
        )

        assert boto3.mock_calls == [
            call("s3"),
            call().get_bucket_cors(Bucket="my-bucket"),
        ]


@pytest.mark.parametrize(
    "options,expected_json",
    (
        (
            [],
            {
                "ID": "set-by-s3-credentials",
                "AllowedOrigins": ["*"],
                "AllowedHeaders": (),
                "AllowedMethods": ["GET"],
                "ExposeHeaders": (),
            },
        ),
        (
            [
                "--allowed-method",
                "GET",
                "--allowed-method",
                "PUT",
                "--allowed-origin",
                "https://www.example.com/",
                "--expose-header",
                "ETag",
            ],
            {
                "ID": "set-by-s3-credentials",
                "AllowedOrigins": ("https://www.example.com/",),
                "AllowedHeaders": (),
                "AllowedMethods": ("GET", "PUT"),
                "ExposeHeaders": ("ETag",),
            },
        ),
        (
            ["--max-age-seconds", 60],
            {
                "ID": "set-by-s3-credentials",
                "AllowedOrigins": ["*"],
                "AllowedHeaders": (),
                "AllowedMethods": ["GET"],
                "ExposeHeaders": (),
                "MaxAgeSeconds": 60,
            },
        ),
    ),
)
def test_set_cors_policy(mocker, options, expected_json):
    boto3 = mocker.patch("boto3.client")
    boto3.return_value = Mock()
    boto3.return_value.put_bucket_cors.return_value = {}
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            cli, ["set-cors-policy", "my-bucket"] + options, catch_exceptions=False
        )
        assert result.exit_code == 0
        assert result.output == ""
        assert boto3.mock_calls == [
            call("s3"),
            call().head_bucket(Bucket="my-bucket"),
            call().put_bucket_cors(
                Bucket="my-bucket", CORSConfiguration={"CORSRules": [expected_json]}
            ),
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


@pytest.mark.parametrize(
    "content",
    (
        '{"AccessKeyId": "access", "SecretAccessKey": "secret"}',
        "[default]\naws_access_key_id=access\naws_secret_access_key=secret",
    ),
)
@pytest.mark.parametrize("use_stdin", (True, False))
def test_auth_option(tmpdir, mocker, content, use_stdin):
    boto3 = mocker.patch("boto3.client")
    boto3.return_value = Mock()
    boto3().get_paginator().paginate.return_value = [{"Users": []}]

    filepath = None
    if use_stdin:
        input = content
        arg = "-"
    else:
        input = None
        filepath = str(tmpdir / "input")
        open(filepath, "w").write(content)
        arg = filepath

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            cli, ["list-users", "-a", arg], catch_exceptions=False, input=input
        )
        assert result.exit_code == 0

    assert boto3.mock_calls == [
        call(),
        call().get_paginator(),
        call("iam", aws_access_key_id="access", aws_secret_access_key="secret"),
        call().get_paginator("list_users"),
        call().get_paginator().paginate(),
    ]


@pytest.mark.parametrize(
    "extra_option", ["--access-key", "--secret-key", "--session-token"]
)
def test_auth_option_errors(extra_option):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["list-users", "-a", "-", extra_option, "blah"],
        catch_exceptions=False,
        input="",
    )
    assert result.exit_code == 1
    assert (
        result.output
        == "Error: --auth cannot be used with --access-key, --secret-key or --session-token\n"
    )


@pytest.mark.parametrize(
    "options,expected",
    (
        ([], READ_WRITE_POLICY),
        (["--read-only"], READ_ONLY_POLICY),
        (["--write-only"], WRITE_ONLY_POLICY),
        (["--prefix", "my-prefix/"], PREFIX_POLICY),
        (
            [
                "--statement",
                '{"Effect": "Allow", "Action": "textract:*", "Resource": "*"}',
            ],
            EXTRA_STATEMENTS_POLICY,
        ),
    ),
)
def test_policy(options, expected):
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["policy", "pytest-bucket-simonw-1"] + options,
        catch_exceptions=False,
    )
    assert json.loads(result.output) == json.loads(expected)


@pytest.mark.parametrize(
    "options,expected",
    (
        (
            [],
            (
                "[\n"
                "  {\n"
                '    "Key": "yolo-causeway-1.jpg",\n'
                '    "LastModified": "2019-12-26 17:00:22+00:00",\n'
                '    "ETag": "\\"87abea888b22089cabe93a0e17cf34a4\\"",\n'
                '    "Size": 5923104,\n'
                '    "StorageClass": "STANDARD"\n'
                "  },\n"
                "  {\n"
                '    "Key": "yolo-causeway-2.jpg",\n'
                '    "LastModified": "2019-12-26 17:00:22+00:00",\n'
                '    "ETag": "\\"87abea888b22089cabe93a0e17cf34a4\\"",\n'
                '    "Size": 5923104,\n'
                '    "StorageClass": "STANDARD"\n'
                "  }\n"
                "]\n"
            ),
        ),
        (
            ["--nl"],
            (
                '{"Key": "yolo-causeway-1.jpg", "LastModified": "2019-12-26 17:00:22+00:00", "ETag": "\\"87abea888b22089cabe93a0e17cf34a4\\"", "Size": 5923104, "StorageClass": "STANDARD"}\n'
                '{"Key": "yolo-causeway-2.jpg", "LastModified": "2019-12-26 17:00:22+00:00", "ETag": "\\"87abea888b22089cabe93a0e17cf34a4\\"", "Size": 5923104, "StorageClass": "STANDARD"}\n'
            ),
        ),
        (
            ["--tsv"],
            (
                "Key\tLastModified\tETag\tSize\tStorageClass\tOwner\n"
                'yolo-causeway-1.jpg\t2019-12-26 17:00:22+00:00\t"""87abea888b22089cabe93a0e17cf34a4"""\t5923104\tSTANDARD\t\n'
                'yolo-causeway-2.jpg\t2019-12-26 17:00:22+00:00\t"""87abea888b22089cabe93a0e17cf34a4"""\t5923104\tSTANDARD\t\n'
            ),
        ),
        (
            ["--csv"],
            (
                "Key,LastModified,ETag,Size,StorageClass,Owner\n"
                'yolo-causeway-1.jpg,2019-12-26 17:00:22+00:00,"""87abea888b22089cabe93a0e17cf34a4""",5923104,STANDARD,\n'
                'yolo-causeway-2.jpg,2019-12-26 17:00:22+00:00,"""87abea888b22089cabe93a0e17cf34a4""",5923104,STANDARD,\n'
            ),
        ),
    ),
)
def test_list_bucket(stub_s3, options, expected):
    stub_s3.add_response(
        "list_objects_v2",
        {
            "Contents": [
                {
                    "Key": "yolo-causeway-1.jpg",
                    "LastModified": "2019-12-26 17:00:22+00:00",
                    "ETag": '"87abea888b22089cabe93a0e17cf34a4"',
                    "Size": 5923104,
                    "StorageClass": "STANDARD",
                },
                {
                    "Key": "yolo-causeway-2.jpg",
                    "LastModified": "2019-12-26 17:00:22+00:00",
                    "ETag": '"87abea888b22089cabe93a0e17cf34a4"',
                    "Size": 5923104,
                    "StorageClass": "STANDARD",
                },
            ]
        },
    )
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["list-bucket", "test-bucket"] + options)
        assert result.exit_code == 0
        assert result.output == expected


def test_list_bucket_empty(stub_s3):
    stub_s3.add_response("list_objects_v2", {})
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["list-bucket", "test-bucket"])
        assert result.exit_code == 0
        assert result.output == "[]\n"


@pytest.fixture
def stub_iam_for_list_roles(stub_iam):
    stub_iam.add_response(
        "list_roles",
        {
            "Roles": [
                {
                    "RoleName": "role-one",
                    "Path": "/",
                    "Arn": "arn:aws:iam::462092780466:role/role-one",
                    "RoleId": "36b2eeee501c5952a8ac119f9e521",
                    "CreateDate": "2020-01-01 00:00:00+00:00",
                }
            ]
        },
    )
    stub_iam.add_response(
        "list_role_policies",
        {"PolicyNames": ["policy-one"]},
    )
    stub_iam.add_response(
        "get_role_policy",
        {
            "RoleName": "role-one",
            "PolicyName": "policy-one",
            "PolicyDocument": '{"foo": "bar}',
        },
    )
    stub_iam.add_response(
        "list_attached_role_policies",
        {"AttachedPolicies": [{"PolicyArn": "arn:123:must-be-at-least-tweny-chars"}]},
    )
    stub_iam.add_response(
        "get_policy",
        {"Policy": {"DefaultVersionId": "v1"}},
    )
    stub_iam.add_response(
        "get_policy_version",
        {"PolicyVersion": {"CreateDate": "2020-01-01 00:00:00+00:00"}},
    )


@pytest.mark.parametrize("details", (False, True))
def test_list_roles_details(stub_iam_for_list_roles, details):
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["list-roles"] + (["--details"] if details else []))
        assert result.exit_code == 0
        expected = {
            "RoleName": "role-one",
            "Path": "/",
            "Arn": "arn:aws:iam::462092780466:role/role-one",
            "RoleId": "36b2eeee501c5952a8ac119f9e521",
            "CreateDate": "2020-01-01 00:00:00+00:00",
            "inline_policies": [
                {
                    "RoleName": "role-one",
                    "PolicyName": "policy-one",
                    "PolicyDocument": '{"foo": "bar}',
                }
            ],
            "attached_policies": [
                {
                    "DefaultVersionId": "v1",
                    "PolicyVersion": {"CreateDate": "2020-01-01 00:00:00+00:00"},
                }
            ],
        }
        if not details:
            expected.pop("inline_policies")
            expected.pop("attached_policies")
        assert json.loads(result.output) == [expected]


def test_list_roles_csv(stub_iam_for_list_roles):
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["list-roles", "--csv", "--details"])
        assert result.exit_code == 0
    assert result.output == (
        "Path,RoleName,RoleId,Arn,CreateDate,AssumeRolePolicyDocument,Description,MaxSessionDuration,PermissionsBoundary,Tags,RoleLastUsed,inline_policies,attached_policies\n"
        '/,role-one,36b2eeee501c5952a8ac119f9e521,arn:aws:iam::462092780466:role/role-one,2020-01-01 00:00:00+00:00,,,,,,,"[\n'
        "  {\n"
        '    ""RoleName"": ""role-one"",\n'
        '    ""PolicyName"": ""policy-one"",\n'
        '    ""PolicyDocument"": ""{\\""foo\\"": \\""bar}""\n'
        "  }\n"
        ']","[\n'
        "  {\n"
        '    ""DefaultVersionId"": ""v1"",\n'
        '    ""PolicyVersion"": {\n'
        '      ""CreateDate"": ""2020-01-01 00:00:00+00:00""\n'
        "    }\n"
        "  }\n"
        ']"\n'
    )


@pytest.mark.parametrize(
    "files,patterns,expected,error",
    (
        # Without arguments return everything
        (None, None, {"one.txt", "directory/two.txt", "directory/three.json"}, None),
        # Positional arguments returns files
        (["one.txt"], None, {"one.txt"}, None),
        (["directory/two.txt"], None, {"directory/two.txt"}, None),
        (["one.txt"], None, {"one.txt"}, None),
        (
            ["directory/two.txt", "directory/three.json"],
            None,
            {"directory/two.txt", "directory/three.json"},
            None,
        ),
        # Invalid positional argument downloads file and shows error
        (
            ["directory/two.txt", "directory/bad.json"],
            None,
            {"directory/two.txt"},
            "Not found: directory/bad.json",
        ),
        # --pattern returns files matching pattern
        (None, ["*e.txt"], {"one.txt"}, None),
        (None, ["*e.txt", "invalid-pattern"], {"one.txt"}, None),
        (None, ["directory/*"], {"directory/two.txt", "directory/three.json"}, None),
        # positional and patterns can be combined
        (["one.txt"], ["directory/*.json"], {"one.txt", "directory/three.json"}, None),
    ),
)
@pytest.mark.parametrize("output", (None, "out"))
def test_get_objects(moto_s3_populated, output, files, patterns, expected, error):
    runner = CliRunner()
    with runner.isolated_filesystem():
        args = ["get-objects", "my-bucket"] + (files or [])
        if patterns:
            for pattern in patterns:
                args.extend(["--pattern", pattern])
        if output:
            args.extend(["--output", output])
        result = runner.invoke(cli, args, catch_exceptions=False)
        if error:
            assert result.exit_code != 0
        else:
            assert result.exit_code == 0
        # Build list of all files in output directory using glob
        output_dir = pathlib.Path(output or ".")
        all_files = {
            str(p.relative_to(output_dir))
            for p in output_dir.glob("**/*")
            if p.is_file()
        }
        assert all_files == expected
        if error:
            assert error in result.output


@pytest.mark.parametrize(
    "args,expected,expected_output",
    (
        (["."], {"one.txt", "directory/two.txt", "directory/three.json"}, None),
        (["one.txt"], {"one.txt"}, None),
        (["directory"], {"directory/two.txt", "directory/three.json"}, None),
        (
            ["directory", "--prefix", "o"],
            {"o/directory/two.txt", "o/directory/three.json"},
            None,
        ),
        # --dry-run tests
        (
            ["directory", "--prefix", "o", "--dry-run"],
            None,
            (
                "directory/two.txt => s3://my-bucket/o/directory/two.txt\n"
                "directory/three.json => s3://my-bucket/o/directory/three.json\n"
            ),
        ),
        (
            [".", "--prefix", "p"],
            {"p/one.txt", "p/directory/two.txt", "p/directory/three.json"},
            None,
        ),
    ),
)
def test_put_objects(moto_s3, args, expected, expected_output):
    runner = CliRunner()
    with runner.isolated_filesystem():
        # Create files
        pathlib.Path("one.txt").write_text("one")
        pathlib.Path("directory").mkdir()
        pathlib.Path("directory/two.txt").write_text("two")
        pathlib.Path("directory/three.json").write_text('{"three": 3}')
        result = runner.invoke(
            cli, ["put-objects", "my-bucket"] + args, catch_exceptions=False
        )
        assert result.exit_code == 0, result.output
        if expected_output:
            # Check all expected output lines are present (order may vary)
            for line in expected_output.strip().split("\n"):
                assert line in result.output
        # Check files were uploaded
        keys = {
            obj["Key"]
            for obj in moto_s3.list_objects(Bucket="my-bucket").get("Contents") or []
        }
        assert keys == (expected or set())


@pytest.mark.parametrize(
    "args,expected,expected_error",
    (
        ([], None, "Error: Specify one or more keys or use --prefix"),
        (
            ["one.txt", "--prefix", "directory/"],
            None,
            "Cannot pass both keys and --prefix",
        ),
        (["one.txt"], ["directory/two.txt", "directory/three.json"], None),
        (["one.txt", "directory/two.txt"], ["directory/three.json"], None),
        (["--prefix", "directory/"], ["one.txt"], None),
    ),
)
def test_delete_objects(moto_s3_populated, args, expected, expected_error):
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            cli, ["delete-objects", "my-bucket"] + args, catch_exceptions=False
        )
        if expected_error:
            assert result.exit_code != 0
            assert expected_error in result.output
        else:
            assert result.exit_code == 0, result.output
            # Check expected files are left in bucket
            keys = {
                obj["Key"]
                for obj in moto_s3_populated.list_objects(Bucket="my-bucket").get(
                    "Contents"
                )
                or []
            }
            assert keys == set(expected)


@pytest.mark.parametrize("arg", ("-d", "--dry-run"))
def test_delete_objects_dry_run(moto_s3_populated, arg):
    runner = CliRunner()

    def get_keys():
        return {
            obj["Key"]
            for obj in moto_s3_populated.list_objects(Bucket="my-bucket").get(
                "Contents"
            )
            or []
        }

    with runner.isolated_filesystem():
        before_keys = get_keys()
        result = runner.invoke(
            cli, ["delete-objects", "my-bucket", "--prefix", "directory/", arg]
        )
        assert result.exit_code == 0
        assert "The following keys would be deleted:" in result.output
        assert "directory/three.json" in result.output
        assert "directory/two.txt" in result.output
        after_keys = get_keys()
        assert before_keys == after_keys


# Tests for localserver command


@pytest.mark.parametrize(
    "value,expected",
    (
        ("30s", 30),
        ("5m", 300),
        ("1h", 3600),
        ("60", 60),  # No suffix means seconds
        ("120s", 120),
        ("10m", 600),
        ("2h", 7200),
    ),
)
def test_refresh_interval_param_valid(value, expected):
    from s3_credentials.cli import RefreshIntervalParam

    param = RefreshIntervalParam()
    assert param.convert(value, None, None) == expected


@pytest.mark.parametrize(
    "value,expected_error",
    (
        ("invalid", "Refresh interval must be of form 30s or 5m or 1h"),
        ("abc123", "Refresh interval must be of form 30s or 5m or 1h"),
        ("-5m", "Refresh interval must be of form 30s or 5m or 1h"),
        ("", "Refresh interval must be of form 30s or 5m or 1h"),
    ),
)
def test_refresh_interval_param_invalid(value, expected_error):
    from s3_credentials.cli import RefreshIntervalParam
    import click

    param = RefreshIntervalParam()
    with pytest.raises(click.exceptions.BadParameter) as exc_info:
        param.convert(value, None, None)
    assert expected_error in str(exc_info.value)


def test_localserver_missing_refresh_interval():
    runner = CliRunner()
    result = runner.invoke(cli, ["localserver", "my-bucket"])
    assert result.exit_code == 2
    assert "Missing option '--refresh-interval'" in result.output


def test_localserver_invalid_refresh_interval():
    runner = CliRunner()
    result = runner.invoke(
        cli, ["localserver", "my-bucket", "--refresh-interval", "invalid"]
    )
    assert result.exit_code == 2
    assert "Refresh interval must be of form 30s or 5m or 1h" in result.output


def test_localserver_read_only_write_only_conflict():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "localserver",
            "my-bucket",
            "--refresh-interval",
            "5m",
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
        cli, ["localserver", "nonexistent-bucket", "--refresh-interval", "5m"]
    )
    assert result.exit_code == 1
    assert "Bucket does not exist: nonexistent-bucket" in result.output


def test_credential_cache_generates_credentials(mocker):
    from s3_credentials.cli import CredentialCache
    import datetime

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
        refresh_interval=300,
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
    assert call_kwargs["DurationSeconds"] == 900  # min 15 minutes


def test_credential_cache_caches_credentials(mocker):
    from s3_credentials.cli import CredentialCache
    import datetime

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
        refresh_interval=300,
        extra_statements=[],
    )

    # Get credentials twice
    creds1 = cache.get_credentials()
    creds2 = cache.get_credentials()

    # Should be the same object (cached)
    assert creds1 is creds2
    # Should only have called assume_role once
    assert mock_sts.assume_role.call_count == 1


def test_credential_cache_refreshes_after_interval(mocker):
    from s3_credentials.cli import CredentialCache
    import datetime
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
        refresh_interval=1,  # 1 second
        extra_statements=[],
    )

    # Get credentials first time
    cache.get_credentials()
    assert mock_sts.assume_role.call_count == 1

    # Wait for interval to expire
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
def test_credential_cache_permission_in_session_name(mocker, permission, expected_permission):
    from s3_credentials.cli import CredentialCache
    import datetime

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
        refresh_interval=300,
        extra_statements=[],
    )

    cache.get_credentials()

    call_kwargs = mock_sts.assume_role.call_args[1]
    assert call_kwargs["RoleSessionName"] == f"s3.{expected_permission}.my-bucket"


def test_credential_cache_policy_generation(mocker):
    from s3_credentials.cli import CredentialCache
    import datetime

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
        refresh_interval=300,
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
    from s3_credentials.cli import make_credential_handler
    import datetime
    import io

    mock_cache = Mock()
    mock_cache.get_credentials.return_value = {
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "SessionToken": "session-token",
        "Expiration": datetime.datetime(2025, 12, 16, 12, 0, 0),
    }

    handler_class = make_credential_handler(mock_cache)

    # Create a mock request
    mock_request = Mock()
    mock_request.makefile.return_value = io.BytesIO(b"GET / HTTP/1.1\r\n\r\n")

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
    assert response_json["AccessKeyId"] == "AKIAIOSFODNN7EXAMPLE"
    assert response_json["SecretAccessKey"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert response_json["SessionToken"] == "session-token"


def test_make_credential_handler_404_on_wrong_path(mocker):
    from s3_credentials.cli import make_credential_handler
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
    from s3_credentials.cli import make_credential_handler
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
