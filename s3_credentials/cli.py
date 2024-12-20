from re import A
import boto3
import botocore
import click
import configparser
from csv import DictWriter
import fnmatch
import io
import itertools
import json
import mimetypes
import os
import pathlib
import re
import sys
import textwrap
from . import policies

PUBLIC_ACCESS_BLOCK_CONFIGURATION = {
    "BlockPublicAcls": False,
    "IgnorePublicAcls": False,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False,
}


def bucket_exists(s3, bucket):
    try:
        s3.head_bucket(Bucket=bucket)
        return True
    except botocore.exceptions.ClientError:
        return False


def user_exists(iam, username):
    try:
        iam.get_user(UserName=username)
        return True
    except iam.exceptions.NoSuchEntityException:
        return False


def common_boto3_options(fn):
    for decorator in reversed(
        (
            click.option(
                "--access-key",
                help="AWS access key ID",
            ),
            click.option(
                "--secret-key",
                help="AWS secret access key",
            ),
            click.option(
                "--session-token",
                help="AWS session token",
            ),
            click.option(
                "--endpoint-url",
                help="Custom endpoint URL",
            ),
            click.option(
                "-a",
                "--auth",
                type=click.File("r"),
                help="Path to JSON/INI file containing credentials",
            ),
        )
    ):
        fn = decorator(fn)
    return fn


def common_output_options(fn):
    for decorator in reversed(
        (
            click.option("--nl", help="Output newline-delimited JSON", is_flag=True),
            click.option("--csv", help="Output CSV", is_flag=True),
            click.option("--tsv", help="Output TSV", is_flag=True),
        )
    ):
        fn = decorator(fn)
    return fn


@click.group()
@click.version_option()
def cli():
    """
    A tool for creating credentials for accessing S3 buckets

    Documentation: https://s3-credentials.readthedocs.io/
    """


class PolicyParam(click.ParamType):
    "Returns string of guaranteed well-formed JSON"
    name = "policy"

    def convert(self, policy, param, ctx):
        if policy.strip().startswith("{"):
            # Verify policy string is valid JSON
            try:
                json.loads(policy)
            except ValueError:
                self.fail("Invalid JSON string")
            return policy
        else:
            # Assume policy is a file path or '-'
            try:
                with click.open_file(policy) as f:
                    contents = f.read()
                    try:
                        json.loads(contents)
                        return contents
                    except ValueError:
                        self.fail(
                            "{} contained invalid JSON".format(
                                "Input" if policy == "-" else "File"
                            )
                        )
            except FileNotFoundError:
                self.fail("File not found")


class DurationParam(click.ParamType):
    name = "duration"
    pattern = re.compile(r"^(\d+)(m|h|s)?$")

    def convert(self, value, param, ctx):
        match = self.pattern.match(value)
        if match is None:
            self.fail("Duration must be of form 3600s or 15m or 2h")
        integer_string, suffix = match.groups()
        integer = int(integer_string)
        if suffix == "m":
            integer *= 60
        elif suffix == "h":
            integer *= 3600
        # Must be between 15 minutes and 12 hours
        if not (15 * 60 <= integer <= 12 * 60 * 60):
            self.fail("Duration must be between 15 minutes and 12 hours")
        return integer


class StatementParam(click.ParamType):
    "Ensures statement is valid JSON with required fields"
    name = "statement"

    def convert(self, statement, param, ctx):
        try:
            data = json.loads(statement)
        except ValueError:
            self.fail("Invalid JSON string")
        if not isinstance(data, dict):
            self.fail("JSON must be an object")
        missing_keys = {"Effect", "Action", "Resource"} - data.keys()
        if missing_keys:
            self.fail(
                "Statement JSON missing required keys: {}".format(
                    ", ".join(sorted(missing_keys))
                )
            )
        return data


@cli.command()
@click.argument(
    "buckets",
    nargs=-1,
    required=True,
)
@click.option("--read-only", help="Only allow reading from the bucket", is_flag=True)
@click.option("--write-only", help="Only allow writing to the bucket", is_flag=True)
@click.option(
    "--prefix", help="Restrict to keys starting with this prefix", default="*"
)
@click.option(
    "extra_statements",
    "--statement",
    multiple=True,
    type=StatementParam(),
    help="JSON statement to add to the policy",
)
@click.option(
    "--public-bucket",
    help="Bucket policy for allowing public access",
    is_flag=True,
)
def policy(buckets, read_only, write_only, prefix, extra_statements, public_bucket):
    """
    Output generated JSON policy for one or more buckets

    Takes the same options as s3-credentials create

    To output a read-only JSON policy for a bucket:

        s3-credentials policy my-bucket --read-only
    """
    "Generate JSON policy for one or more buckets"
    if public_bucket:
        if len(buckets) != 1:
            raise click.ClickException(
                "--public-bucket policy can only be generated for a single bucket"
            )
        click.echo(
            json.dumps(policies.bucket_policy_allow_all_get(buckets[0]), indent=4)
        )
        return
    permission = "read-write"
    if read_only:
        permission = "read-only"
    if write_only:
        permission = "write-only"
    statements = []
    if permission == "read-write":
        for bucket in buckets:
            statements.extend(policies.read_write_statements(bucket, prefix))
    elif permission == "read-only":
        for bucket in buckets:
            statements.extend(policies.read_only_statements(bucket, prefix))
    elif permission == "write-only":
        for bucket in buckets:
            statements.extend(policies.write_only_statements(bucket, prefix))
    else:
        assert False, "Unknown permission: {}".format(permission)
    if extra_statements:
        statements.extend(extra_statements)
    bucket_access_policy = policies.wrap_policy(statements)
    click.echo(json.dumps(bucket_access_policy, indent=4))


@cli.command()
@click.argument(
    "buckets",
    nargs=-1,
    required=True,
)
@click.option(
    "format_",
    "-f",
    "--format",
    type=click.Choice(["ini", "json"]),
    default="json",
    help="Output format for credentials",
)
@click.option(
    "-d",
    "--duration",
    type=DurationParam(),
    help="How long should these credentials work for? Default is forever, use 3600 for 3600 seconds, 15m for 15 minutes, 1h for 1 hour",
)
@click.option("--username", help="Username to create or existing user to use")
@click.option(
    "-c",
    "--create-bucket",
    help="Create buckets if they do not already exist",
    is_flag=True,
)
@click.option(
    "--prefix", help="Restrict to keys starting with this prefix", default="*"
)
@click.option(
    "--public",
    help="Make the created bucket public: anyone will be able to download files if they know their name",
    is_flag=True,
)
@click.option(
    "--website",
    help="Configure bucket to act as a website, using index.html and error.html",
    is_flag=True,
)
@click.option("--read-only", help="Only allow reading from the bucket", is_flag=True)
@click.option("--write-only", help="Only allow writing to the bucket", is_flag=True)
@click.option(
    "--policy",
    type=PolicyParam(),
    help="Path to a policy.json file, or literal JSON string - $!BUCKET_NAME!$ will be replaced with the name of the bucket",
)
@click.option(
    "extra_statements",
    "--statement",
    multiple=True,
    type=StatementParam(),
    help="JSON statement to add to the policy",
)
@click.option("--bucket-region", help="Region in which to create buckets")
@click.option("--silent", help="Don't show performed steps", is_flag=True)
@click.option("--dry-run", help="Show steps without executing them", is_flag=True)
@click.option(
    "--user-permissions-boundary",
    help=(
        "Custom permissions boundary to use for created users, or 'none' to "
        "create without. Defaults to limiting to S3 based on "
        "--read-only and --write-only options."
    ),
)
@common_boto3_options
def create(
    buckets,
    format_,
    duration,
    username,
    create_bucket,
    prefix,
    public,
    website,
    read_only,
    write_only,
    policy,
    extra_statements,
    bucket_region,
    user_permissions_boundary,
    silent,
    dry_run,
    **boto_options,
):
    """
    Create and return new AWS credentials for specified S3 buckets - optionally
    also creating the bucket if it does not yet exist.

    To create a new bucket and output read-write credentials:

        s3-credentials create my-new-bucket -c

    To create read-only credentials for an existing bucket:

        s3-credentials create my-existing-bucket --read-only

    To create write-only credentials that are only valid for 15 minutes:

        s3-credentials create my-existing-bucket --write-only -d 15m
    """
    if read_only and write_only:
        raise click.ClickException(
            "Cannot use --read-only and --write-only at the same time"
        )
    extra_statements = list(extra_statements)

    def log(message):
        if not silent:
            click.echo(message, err=True)

    permission = "read-write"
    if read_only:
        permission = "read-only"
    if write_only:
        permission = "write-only"

    if not user_permissions_boundary and (policy or extra_statements):
        user_permissions_boundary = "none"

    if website:
        public = True

    s3 = None
    iam = None
    sts = None

    if not dry_run:
        s3 = make_client("s3", **boto_options)
        iam = make_client("iam", **boto_options)
        sts = make_client("sts", **boto_options)

    # Verify buckets
    for bucket in buckets:
        # Create bucket if it doesn't exist
        if dry_run or (not bucket_exists(s3, bucket)):
            if (not dry_run) and (not create_bucket):
                raise click.ClickException(
                    "Bucket does not exist: {} - try --create-bucket to create it".format(
                        bucket
                    )
                )
            if dry_run or create_bucket:
                kwargs = {}
                if bucket_region:
                    kwargs = {
                        "CreateBucketConfiguration": {
                            "LocationConstraint": bucket_region
                        }
                    }
                bucket_policy = {}
                if public:
                    bucket_policy = policies.bucket_policy_allow_all_get(bucket)

                if dry_run:
                    click.echo(
                        "Would create bucket: '{}'{}".format(
                            bucket,
                            (
                                " with args {}".format(json.dumps(kwargs, indent=4))
                                if kwargs
                                else ""
                            ),
                        )
                    )
                    if public:
                        click.echo(
                            "... then add this public access block configuration:"
                        )
                        click.echo(json.dumps(PUBLIC_ACCESS_BLOCK_CONFIGURATION))

                    if bucket_policy:
                        click.echo("... then attach the following bucket policy to it:")
                        click.echo(json.dumps(bucket_policy, indent=4))
                    if website:
                        click.echo(
                            "... then configure index.html and error.html website settings"
                        )
                else:
                    s3.create_bucket(Bucket=bucket, **kwargs)
                    info = "Created bucket: {}".format(bucket)
                    if bucket_region:
                        info += " in region: {}".format(bucket_region)
                    log(info)

                    if public:
                        s3.put_public_access_block(
                            Bucket=bucket,
                            PublicAccessBlockConfiguration=PUBLIC_ACCESS_BLOCK_CONFIGURATION,
                        )
                        log("Set public access block configuration")

                    if bucket_policy:
                        s3.put_bucket_policy(
                            Bucket=bucket, Policy=json.dumps(bucket_policy)
                        )
                        log("Attached bucket policy allowing public access")
                    if website:
                        s3.put_bucket_website(
                            Bucket=bucket,
                            WebsiteConfiguration={
                                "ErrorDocument": {"Key": "error.html"},
                                "IndexDocument": {"Suffix": "index.html"},
                            },
                        )
                        log(
                            "Configured website: IndexDocument=index.html, ErrorDocument=error.html"
                        )

    # At this point the buckets definitely exist - create the inline policy for assume_role()
    assume_role_policy = {}
    if policy:
        assume_role_policy = json.loads(policy.replace("$!BUCKET_NAME!$", bucket))
    else:
        statements = []
        if permission == "read-write":
            for bucket in buckets:
                statements.extend(policies.read_write_statements(bucket, prefix))
        elif permission == "read-only":
            for bucket in buckets:
                statements.extend(policies.read_only_statements(bucket, prefix))
        elif permission == "write-only":
            for bucket in buckets:
                statements.extend(policies.write_only_statements(bucket, prefix))
        else:
            assert False, "Unknown permission: {}".format(permission)
        statements.extend(extra_statements)
        assume_role_policy = policies.wrap_policy(statements)

    if duration:
        # We're going to use sts.assume_role() rather than creating a user
        if dry_run:
            click.echo("Would ensure role: 's3-credentials.AmazonS3FullAccess'")
            click.echo(
                "Would assume role using following policy for {} seconds:".format(
                    duration
                )
            )
            click.echo(json.dumps(assume_role_policy, indent=4))
        else:
            s3_role_arn = ensure_s3_role_exists(iam, sts)
            log("Assume role against {} for {}s".format(s3_role_arn, duration))
            credentials_response = sts.assume_role(
                RoleArn=s3_role_arn,
                RoleSessionName="s3.{permission}.{buckets}".format(
                    permission="custom" if (policy or extra_statements) else permission,
                    buckets=",".join(buckets),
                ),
                Policy=json.dumps(assume_role_policy),
                DurationSeconds=duration,
            )
            if format_ == "ini":
                click.echo(
                    (
                        "[default]\naws_access_key_id={}\n"
                        "aws_secret_access_key={}\naws_session_token={}"
                    ).format(
                        credentials_response["Credentials"]["AccessKeyId"],
                        credentials_response["Credentials"]["SecretAccessKey"],
                        credentials_response["Credentials"]["SessionToken"],
                    )
                )
            else:
                click.echo(
                    json.dumps(
                        credentials_response["Credentials"], indent=4, default=str
                    )
                )
        return
    # No duration, so wo create a new user so we can issue non-expiring credentials
    if not username:
        # Default username is "s3.read-write.bucket1,bucket2"
        username = "s3.{permission}.{buckets}".format(
            permission="custom" if (policy or extra_statements) else permission,
            buckets=",".join(buckets),
        )
    if dry_run or (not user_exists(iam, username)):
        kwargs = {"UserName": username}
        if user_permissions_boundary != "none":
            # This is a user-account level limitation, it does not grant
            # permissions on its own but is a useful extra level of defense
            # https://github.com/simonw/s3-credentials/issues/1#issuecomment-958201717
            if not user_permissions_boundary:
                # Pick one based on --read-only/--write-only
                if read_only:
                    user_permissions_boundary = (
                        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
                    )
                else:
                    # Need full access in order to be able to write
                    user_permissions_boundary = (
                        "arn:aws:iam::aws:policy/AmazonS3FullAccess"
                    )
            kwargs["PermissionsBoundary"] = user_permissions_boundary
        info = " user: '{}'".format(username)
        if user_permissions_boundary != "none":
            info += " with permissions boundary: '{}'".format(user_permissions_boundary)
        if dry_run:
            click.echo("Would create{}".format(info))
        else:
            iam.create_user(**kwargs)
            log("Created {}".format(info))

    # Add inline policies to the user so they can access the buckets
    user_policy = {}
    for bucket in buckets:
        policy_name = "s3.{permission}.{bucket}".format(
            permission="custom" if (policy or extra_statements) else permission,
            bucket=bucket,
        )
        if policy:
            user_policy = json.loads(policy.replace("$!BUCKET_NAME!$", bucket))
        else:
            if permission == "read-write":
                user_policy = policies.read_write(bucket, prefix, extra_statements)
            elif permission == "read-only":
                user_policy = policies.read_only(bucket, prefix, extra_statements)
            elif permission == "write-only":
                user_policy = policies.write_only(bucket, prefix, extra_statements)
            else:
                assert False, "Unknown permission: {}".format(permission)

        if dry_run:
            click.echo(
                "Would attach policy called '{}' to user '{}', details:\n{}".format(
                    policy_name,
                    username,
                    json.dumps(user_policy, indent=4),
                )
            )
        else:
            iam.put_user_policy(
                PolicyDocument=json.dumps(user_policy),
                PolicyName=policy_name,
                UserName=username,
            )
            log("Attached policy {} to user {}".format(policy_name, username))

    # Retrieve and print out the credentials
    if dry_run:
        click.echo("Would call create access key for user '{}'".format(username))
    else:
        response = iam.create_access_key(
            UserName=username,
        )
        log("Created access key for user: {}".format(username))
        if format_ == "ini":
            click.echo(
                ("[default]\naws_access_key_id={}\n" "aws_secret_access_key={}").format(
                    response["AccessKey"]["AccessKeyId"],
                    response["AccessKey"]["SecretAccessKey"],
                )
            )
        elif format_ == "json":
            click.echo(json.dumps(response["AccessKey"], indent=4, default=str))


@cli.command()
@common_boto3_options
def whoami(**boto_options):
    "Identify currently authenticated user"
    sts = make_client("sts", **boto_options)
    identity = sts.get_caller_identity()
    identity.pop("ResponseMetadata")
    click.echo(json.dumps(identity, indent=4, default=str))


@cli.command()
@common_output_options
@common_boto3_options
def list_users(nl, csv, tsv, **boto_options):
    """
    List all users for this account

        s3-credentials list-users

    Add --csv or --csv for CSV or TSV format:

        s3-credentials list-users --csv
    """
    iam = make_client("iam", **boto_options)
    output(
        paginate(iam, "list_users", "Users"),
        (
            "UserName",
            "UserId",
            "Arn",
            "Path",
            "CreateDate",
            "PasswordLastUsed",
            "PermissionsBoundary",
            "Tags",
        ),
        nl,
        csv,
        tsv,
    )


@cli.command()
@click.argument("role_names", nargs=-1)
@click.option("--details", help="Include attached policies (slower)", is_flag=True)
@common_output_options
@common_boto3_options
def list_roles(role_names, details, nl, csv, tsv, **boto_options):
    """
    List roles

    To list all roles for this AWS account:

        s3-credentials list-roles

    Add --csv or --csv for CSV or TSV format:

        s3-credentials list-roles --csv

    For extra details per role (much slower) add --details

        s3-credentials list-roles --details
    """
    iam = make_client("iam", **boto_options)
    headers = (
        "Path",
        "RoleName",
        "RoleId",
        "Arn",
        "CreateDate",
        "AssumeRolePolicyDocument",
        "Description",
        "MaxSessionDuration",
        "PermissionsBoundary",
        "Tags",
        "RoleLastUsed",
    )
    if details:
        headers += ("inline_policies", "attached_policies")

    def iterate():
        for role in paginate(iam, "list_roles", "Roles"):
            if role_names and role["RoleName"] not in role_names:
                continue
            if details:
                role_name = role["RoleName"]
                role["inline_policies"] = []
                # Get inline policy names, then policy for each one
                for policy_name in paginate(
                    iam, "list_role_policies", "PolicyNames", RoleName=role_name
                ):
                    role_policy_response = iam.get_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name,
                    )
                    role_policy_response.pop("ResponseMetadata", None)
                    role["inline_policies"].append(role_policy_response)

                # Get attached managed policies
                role["attached_policies"] = []
                for attached in paginate(
                    iam,
                    "list_attached_role_policies",
                    "AttachedPolicies",
                    RoleName=role_name,
                ):
                    policy_arn = attached["PolicyArn"]
                    attached_policy_response = iam.get_policy(
                        PolicyArn=policy_arn,
                    )
                    policy_details = attached_policy_response["Policy"]
                    # Also need to fetch the policy JSON
                    version_id = policy_details["DefaultVersionId"]
                    policy_version_response = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=version_id,
                    )
                    policy_details["PolicyVersion"] = policy_version_response[
                        "PolicyVersion"
                    ]
                    role["attached_policies"].append(policy_details)

            yield role

    output(iterate(), headers, nl, csv, tsv)


@cli.command()
@click.argument("usernames", nargs=-1)
@common_boto3_options
def list_user_policies(usernames, **boto_options):
    """
    List inline policies for specified users

        s3-credentials list-user-policies username

    Returns policies for all users if no usernames are provided.
    """
    iam = make_client("iam", **boto_options)
    if not usernames:
        usernames = [user["UserName"] for user in paginate(iam, "list_users", "Users")]
    for username in usernames:
        click.echo("User: {}".format(username))
        for policy_name in paginate(
            iam, "list_user_policies", "PolicyNames", UserName=username
        ):
            click.echo("PolicyName: {}".format(policy_name))
            policy_response = iam.get_user_policy(
                UserName=username, PolicyName=policy_name
            )
            click.echo(
                json.dumps(policy_response["PolicyDocument"], indent=4, default=str)
            )


@cli.command()
@click.argument("buckets", nargs=-1)
@click.option("--details", help="Include extra bucket details (slower)", is_flag=True)
@common_output_options
@common_boto3_options
def list_buckets(buckets, details, nl, csv, tsv, **boto_options):
    """
    List buckets

    To list all buckets and their creation time as JSON:

        s3-credentials list-buckets

    Add --csv or --csv for CSV or TSV format:

        s3-credentials list-buckets --csv

    For extra details per bucket (much slower) add --details

        s3-credentials list-buckets --details
    """
    s3 = make_client("s3", **boto_options)

    headers = ["Name", "CreationDate"]
    if details:
        headers += ["bucket_acl", "public_access_block", "bucket_website"]

    def iterator():
        for bucket in s3.list_buckets()["Buckets"]:
            if buckets and (bucket["Name"] not in buckets):
                continue
            if details:
                bucket_acl = dict(
                    (key, value)
                    for key, value in s3.get_bucket_acl(
                        Bucket=bucket["Name"],
                    ).items()
                    if key != "ResponseMetadata"
                )
                region = s3.get_bucket_location(Bucket=bucket["Name"])[
                    "LocationConstraint"
                ]
                if region is None:
                    # "Buckets in Region us-east-1 have a LocationConstraint of null"
                    region = "us-east-1"
                try:
                    pab = s3.get_public_access_block(
                        Bucket=bucket["Name"],
                    )["PublicAccessBlockConfiguration"]
                except s3.exceptions.ClientError:
                    pab = None
                try:
                    bucket_website = dict(
                        (key, value)
                        for key, value in s3.get_bucket_website(
                            Bucket=bucket["Name"],
                        ).items()
                        if key != "ResponseMetadata"
                    )
                    bucket_website["url"] = (
                        "http://{}.s3-website.{}.amazonaws.com/".format(
                            bucket["Name"], region
                        )
                    )
                except s3.exceptions.ClientError:
                    bucket_website = None
                bucket["region"] = region
                bucket["bucket_acl"] = bucket_acl
                bucket["public_access_block"] = pab
                bucket["bucket_website"] = bucket_website
            yield bucket

    output(iterator(), headers, nl, csv, tsv)


@cli.command()
@click.argument("usernames", nargs=-1, required=True)
@common_boto3_options
def delete_user(usernames, **boto_options):
    """
    Delete specified users, their access keys and their inline policies


        s3-credentials delete-user username1 username2
    """
    iam = make_client("iam", **boto_options)
    for username in usernames:
        click.echo("User: {}".format(username))
        # Fetch and delete their policies
        policy_names_to_delete = list(
            paginate(iam, "list_user_policies", "PolicyNames", UserName=username)
        )
        for policy_name in policy_names_to_delete:
            iam.delete_user_policy(
                UserName=username,
                PolicyName=policy_name,
            )
            click.echo("  Deleted policy: {}".format(policy_name))
        # Fetch and delete their access keys
        access_key_ids_to_delete = [
            access_key["AccessKeyId"]
            for access_key in paginate(
                iam, "list_access_keys", "AccessKeyMetadata", UserName=username
            )
        ]
        for access_key_id in access_key_ids_to_delete:
            iam.delete_access_key(
                UserName=username,
                AccessKeyId=access_key_id,
            )
            click.echo("  Deleted access key: {}".format(access_key_id))
        iam.delete_user(UserName=username)
        click.echo("  Deleted user")


def make_client(service, access_key, secret_key, session_token, endpoint_url, auth):
    if auth:
        if access_key or secret_key or session_token:
            raise click.ClickException(
                "--auth cannot be used with --access-key, --secret-key or --session-token"
            )
        auth_content = auth.read().strip()
        if auth_content.startswith("{"):
            # Treat as JSON
            decoded = json.loads(auth_content)
            access_key = decoded.get("AccessKeyId")
            secret_key = decoded.get("SecretAccessKey")
            session_token = decoded.get("SessionToken")
        else:
            # Treat as INI
            config = configparser.ConfigParser()
            config.read_string(auth_content)
            # Use the first section that has an aws_access_key_id
            for section in config.sections():
                if "aws_access_key_id" in config[section]:
                    access_key = config[section].get("aws_access_key_id")
                    secret_key = config[section].get("aws_secret_access_key")
                    session_token = config[section].get("aws_session_token")
                    break
    kwargs = {}
    if access_key:
        kwargs["aws_access_key_id"] = access_key
    if secret_key:
        kwargs["aws_secret_access_key"] = secret_key
    if session_token:
        kwargs["aws_session_token"] = session_token
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
    return boto3.client(service, **kwargs)


def ensure_s3_role_exists(iam, sts):
    "Create s3-credentials.AmazonS3FullAccess role if not exists, return ARN"
    role_name = "s3-credentials.AmazonS3FullAccess"
    account_id = sts.get_caller_identity()["Account"]
    try:
        role = iam.get_role(RoleName=role_name)
        return role["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        create_role_response = iam.create_role(
            Description=(
                "Role used by the s3-credentials tool to create time-limited "
                "credentials that are restricted to specific buckets"
            ),
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": "arn:aws:iam::{}:root".format(account_id)
                            },
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
            MaxSessionDuration=12 * 60 * 60,
        )
        # Attach AmazonS3FullAccess to it - note that even though we use full access
        # on the role itself any time we call sts.assume_role() we attach an additional
        # policy to ensure reduced access for the temporary credentials
        iam.attach_role_policy(
            RoleName="s3-credentials.AmazonS3FullAccess",
            PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess",
        )
        return create_role_response["Role"]["Arn"]


@cli.command()
@click.argument("bucket")
@click.option("--prefix", help="List keys starting with this prefix")
@click.option("--urls", is_flag=True, help="Show URLs for each key")
@common_output_options
@common_boto3_options
def list_bucket(bucket, prefix, urls, nl, csv, tsv, **boto_options):
    """
    List contents of bucket

    To list the contents of a bucket as JSON:

        s3-credentials list-bucket my-bucket

    Add --csv or --csv for CSV or TSV format:

        s3-credentials list-bucket my-bucket --csv

    Add --urls to get an extra URL field for each key:

        s3-credentials list-bucket my-bucket --urls
    """
    s3 = make_client("s3", **boto_options)
    kwargs = {"Bucket": bucket}
    if prefix:
        kwargs["Prefix"] = prefix

    fields = ["Key", "LastModified", "ETag", "Size", "StorageClass", "Owner"]
    if urls:
        fields.append("URL")

    items = paginate(s3, "list_objects_v2", "Contents", **kwargs)
    if urls:
        items = (
            dict(item, URL="https://s3.amazonaws.com/{}/{}".format(bucket, item["Key"]))
            for item in items
        )

    try:
        output(
            items,
            fields,
            nl,
            csv,
            tsv,
        )
    except botocore.exceptions.ClientError as e:
        raise click.ClickException(e)


@cli.command()
@click.argument("bucket")
@click.argument("key")
@click.argument(
    "path",
    type=click.Path(
        exists=True, file_okay=True, dir_okay=False, readable=True, allow_dash=True
    ),
)
@click.option(
    "--content-type",
    help="Content-Type to use (default is auto-detected based on file extension)",
)
@click.option("silent", "-s", "--silent", is_flag=True, help="Don't show progress bar")
@common_boto3_options
def put_object(bucket, key, path, content_type, silent, **boto_options):
    """
    Upload an object to an S3 bucket

    To upload a file to /my-key.txt in the my-bucket bucket:

        s3-credentials put-object my-bucket my-key.txt /path/to/file.txt

    Use - to upload content from standard input:

        echo "Hello" | s3-credentials put-object my-bucket hello.txt -
    """
    s3 = make_client("s3", **boto_options)
    size = None
    extra_args = {}
    if path == "-":
        # boto needs to be able to seek
        fp = io.BytesIO(sys.stdin.buffer.read())
        if not silent:
            size = fp.getbuffer().nbytes
    else:
        if not content_type:
            content_type = mimetypes.guess_type(path)[0]
        fp = click.open_file(path, "rb")
        if not silent:
            size = os.path.getsize(path)
    if content_type is not None:
        extra_args["ContentType"] = content_type
    if not silent:
        # Show progress bar
        with click.progressbar(length=size, label="Uploading", file=sys.stderr) as bar:
            s3.upload_fileobj(
                fp, bucket, key, Callback=bar.update, ExtraArgs=extra_args
            )
    else:
        s3.upload_fileobj(fp, bucket, key, ExtraArgs=extra_args)


@cli.command()
@click.argument("bucket")
@click.argument(
    "objects",
    nargs=-1,
    required=True,
)
@click.option(
    "--prefix",
    help="Prefix to add to the files within the bucket",
)
@click.option("silent", "-s", "--silent", is_flag=True, help="Don't show progress bar")
@click.option("--dry-run", help="Show steps without executing them", is_flag=True)
@common_boto3_options
def put_objects(bucket, objects, prefix, silent, dry_run, **boto_options):
    """
    Upload multiple objects to an S3 bucket

    Pass one or more files to upload them:

        s3-credentials put-objects my-bucket one.txt two.txt

    These will be saved to the root of the bucket. To save to a different location
    use the --prefix option:

        s3-credentials put-objects my-bucket one.txt two.txt --prefix my-folder

    This will upload them my-folder/one.txt and my-folder/two.txt.

    If you pass a directory it will be uploaded recursively:

        s3-credentials put-objects my-bucket my-folder

    This will create keys in my-folder/... in the S3 bucket.

    To upload all files in a folder to the root of the bucket instead use this:

        s3-credentials put-objects my-bucket my-folder/*
    """
    s3 = make_client("s3", **boto_options)
    if prefix and not prefix.endswith("/"):
        prefix = prefix + "/"
    total_size = 0
    # Figure out files to upload and their keys
    paths = []  # (path, key)
    for obj in objects:
        path = pathlib.Path(obj)
        if path.is_file():
            # Just use the filename as the key
            paths.append((path, path.name))
        elif path.is_dir():
            # Key is the relative path within the directory
            for p in path.glob("**/*"):
                if p.is_file():
                    paths.append((p, str(p.relative_to(path.parent))))

    def upload(path, key, callback=None):
        final_key = key
        if prefix:
            final_key = prefix + key
        if dry_run:
            click.echo("{} => s3://{}/{}".format(path, bucket, final_key))
        else:
            s3.upload_file(
                Filename=str(path), Bucket=bucket, Key=final_key, Callback=callback
            )

    if not silent and not dry_run:
        total_size = sum(p[0].stat().st_size for p in paths)
        with click.progressbar(
            length=total_size,
            label="Uploading {} ({} file{})".format(
                format_bytes(total_size),
                len(paths),
                "s" if len(paths) != 1 else "",
            ),
            file=sys.stderr,
        ) as bar:
            for path, key in paths:
                upload(path, key, bar.update)
    else:
        for path, key in paths:
            upload(path, key)


@cli.command()
@click.argument("bucket")
@click.argument("key")
@click.option(
    "output",
    "-o",
    "--output",
    type=click.Path(file_okay=True, dir_okay=False, writable=True, allow_dash=False),
    help="Write to this file instead of stdout",
)
@common_boto3_options
def get_object(bucket, key, output, **boto_options):
    """
    Download an object from an S3 bucket

    To see the contents of the bucket on standard output:

        s3-credentials get-object my-bucket hello.txt

    To save to a file:

        s3-credentials get-object my-bucket hello.txt -o hello.txt
    """
    s3 = make_client("s3", **boto_options)
    if not output:
        fp = sys.stdout.buffer
    else:
        fp = click.open_file(output, "wb")
    s3.download_fileobj(bucket, key, fp)


@cli.command()
@click.argument("bucket")
@click.argument(
    "keys",
    nargs=-1,
    required=False,
)
@click.option(
    "output",
    "-o",
    "--output",
    type=click.Path(file_okay=False, dir_okay=True, writable=True, allow_dash=False),
    help="Write to this directory instead of one matching the bucket name",
)
@click.option(
    "patterns",
    "-p",
    "--pattern",
    multiple=True,
    help="Glob patterns for files to download, e.g. '*/*.js'",
)
@click.option("silent", "-s", "--silent", is_flag=True, help="Don't show progress bar")
@common_boto3_options
def get_objects(bucket, keys, output, patterns, silent, **boto_options):
    """
    Download multiple objects from an S3 bucket

    To download everything, run:

        s3-credentials get-objects my-bucket

    Files will be saved to a directory called my-bucket. Use -o dirname to save to a
    different directory.

    To download specific keys, list them:

        s3-credentials get-objects my-bucket one.txt path/two.txt

    To download files matching a glob-style pattern, use:

        s3-credentials get-objects my-bucket --pattern '*/*.js'
    """
    s3 = make_client("s3", **boto_options)

    # If user specified keys and no patterns, use the keys they specified
    keys_to_download = list(keys)
    key_sizes = {}

    if keys and not silent:
        # Get sizes of those keys for progress bar
        for key in keys:
            try:
                key_sizes[key] = s3.head_object(Bucket=bucket, Key=key)["ContentLength"]
            except botocore.exceptions.ClientError:
                # Ignore errors - they will be reported later
                key_sizes[key] = 0

    if (not keys) or patterns:
        # Fetch all keys, then filter them if --pattern
        all_key_infos = list(paginate(s3, "list_objects_v2", "Contents", Bucket=bucket))
        if patterns:
            filtered = []
            for pattern in patterns:
                filtered.extend(
                    fnmatch.filter((k["Key"] for k in all_key_infos), pattern)
                )
            keys_to_download.extend(filtered)
        else:
            keys_to_download.extend(k["Key"] for k in all_key_infos)
        if not silent:
            key_set = set(keys_to_download)
            for key in all_key_infos:
                if key["Key"] in key_set:
                    key_sizes[key["Key"]] = key["Size"]

    output_dir = pathlib.Path(output or ".")
    if not output_dir.exists():
        output_dir.mkdir(parents=True)

    errors = []

    def download(key, callback=None):
        # Ensure directory for key exists
        key_dir = (output_dir / key).parent
        if not key_dir.exists():
            key_dir.mkdir(parents=True)
        try:
            s3.download_file(bucket, key, str(output_dir / key), Callback=callback)
        except botocore.exceptions.ClientError as e:
            errors.append("Not found: {}".format(key))

    if not silent:
        total_size = sum(key_sizes.values())
        with click.progressbar(
            length=total_size,
            label="Downloading {} ({} file{})".format(
                format_bytes(total_size),
                len(key_sizes),
                "s" if len(key_sizes) != 1 else "",
            ),
            file=sys.stderr,
        ) as bar:
            for key in keys_to_download:
                download(key, bar.update)
    else:
        for key in keys_to_download:
            download(key)

    if errors:
        raise click.ClickException("\n".join(errors))


@cli.command()
@click.argument("bucket")
@click.option(
    "allowed_methods",
    "-m",
    "--allowed-method",
    multiple=True,
    help="Allowed method e.g. GET",
)
@click.option(
    "allowed_headers",
    "-h",
    "--allowed-header",
    multiple=True,
    help="Allowed header e.g. Authorization",
)
@click.option(
    "allowed_origins",
    "-o",
    "--allowed-origin",
    multiple=True,
    help="Allowed origin e.g. https://www.example.com/",
)
@click.option(
    "expose_headers",
    "-e",
    "--expose-header",
    multiple=True,
    help="Header to expose e.g. ETag",
)
@click.option(
    "max_age_seconds",
    "--max-age-seconds",
    type=int,
    help="How long to cache preflight requests",
)
@common_boto3_options
def set_cors_policy(
    bucket,
    allowed_methods,
    allowed_headers,
    allowed_origins,
    expose_headers,
    max_age_seconds,
    **boto_options,
):
    """
    Set CORS policy for a bucket

    To allow GET requests from any origin:

        s3-credentials set-cors-policy my-bucket

    To allow GET and PUT from a specific origin and expose ETag headers:

    \b
        s3-credentials set-cors-policy my-bucket \\
          --allowed-method GET \\
          --allowed-method PUT \\
          --allowed-origin https://www.example.com/ \\
          --expose-header ETag
    """
    s3 = make_client("s3", **boto_options)
    if not bucket_exists(s3, bucket):
        raise click.ClickException("Bucket {} does not exists".format(bucket))

    cors_rule = {
        "ID": "set-by-s3-credentials",
        "AllowedOrigins": allowed_origins or ["*"],
        "AllowedHeaders": allowed_headers,
        "AllowedMethods": allowed_methods or ["GET"],
        "ExposeHeaders": expose_headers,
    }
    if max_age_seconds:
        cors_rule["MaxAgeSeconds"] = max_age_seconds

    try:
        s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": [cors_rule]})
    except botocore.exceptions.ClientError as e:
        raise click.ClickException(e)


@cli.command()
@click.argument("bucket")
@common_boto3_options
def get_cors_policy(bucket, **boto_options):
    """
    Get CORS policy for a bucket

       s3-credentials get-cors-policy my-bucket

    Returns the CORS policy for this bucket, if set, as JSON
    """
    s3 = make_client("s3", **boto_options)
    try:
        response = s3.get_bucket_cors(Bucket=bucket)
    except botocore.exceptions.ClientError as e:
        raise click.ClickException(e)
    click.echo(json.dumps(response["CORSRules"], indent=4, default=str))


@cli.command()
@click.argument("bucket")
@common_boto3_options
def get_bucket_policy(bucket, **boto_options):
    """
    Get bucket policy for a bucket

       s3-credentials get-bucket-policy my-bucket

    Returns the bucket policy for this bucket, if set, as JSON
    """
    s3 = make_client("s3", **boto_options)
    try:
        response = s3.get_bucket_policy(Bucket=bucket)
    except botocore.exceptions.ClientError as e:
        raise click.ClickException(e)
    click.echo(json.dumps(json.loads(response["Policy"]), indent=4, default=str))


@cli.command()
@click.argument("bucket")
@click.option("--policy-file", type=click.File("r"))
@click.option("--allow-all-get", is_flag=True, help="Allow GET requests from all")
@common_boto3_options
def set_bucket_policy(bucket, policy_file, allow_all_get, **boto_options):
    """
    Set bucket policy for a bucket

        s3-credentials set-bucket-policy my-bucket --policy-file policy.json

    Or to set a policy that allows GET requests from all:

        s3-credentials set-bucket-policy my-bucket --allow-all-get
    """
    s3 = make_client("s3", **boto_options)
    if allow_all_get and policy_file:
        raise click.ClickException("Cannot pass both --allow-all-get and --policy-file")
    if allow_all_get:
        policy = policies.bucket_policy_allow_all_get(bucket)
    else:
        policy = json.load(policy_file)
    try:
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    except botocore.exceptions.ClientError as e:
        raise click.ClickException(e)
    click.echo("Policy set:\n" + json.dumps(policy, indent=4), err=True)


def without_response_metadata(data):
    return dict(
        (key, value) for key, value in data.items() if key != "ResponseMetadata"
    )


@cli.command()
@click.argument("bucket")
@common_boto3_options
def debug_bucket(bucket, **boto_options):
    """
    Run a bunch of diagnostics to help debug a bucket

       s3-credentials debug-bucket my-bucket
    """
    s3 = make_client("s3", **boto_options)

    try:
        bucket_acl = s3.get_bucket_acl(Bucket=bucket)
        click.echo("Bucket ACL:")
        click.echo(json.dumps(without_response_metadata(bucket_acl), indent=4))
    except Exception as ex:
        print(f"Error checking bucket ACL: {ex}")

    try:
        bucket_policy_status = s3.get_bucket_policy_status(Bucket=bucket)
        click.echo("Bucket policy status:")
        click.echo(
            json.dumps(without_response_metadata(bucket_policy_status), indent=4)
        )
    except Exception as ex:
        print(f"Error checking bucket policy status: {ex}")

    try:
        bucket_public_access_block = s3.get_public_access_block(Bucket=bucket)
        click.echo("Bucket public access block:")
        click.echo(
            json.dumps(without_response_metadata(bucket_public_access_block), indent=4)
        )
    except Exception as ex:
        print(f"Error checking bucket public access block: {ex}")


@cli.command()
@click.argument("bucket")
@click.argument(
    "keys",
    nargs=-1,
)
@click.option(
    "--prefix",
    help="Delete everything with this prefix",
)
@click.option(
    "silent", "-s", "--silent", is_flag=True, help="Don't show informational output"
)
@click.option(
    "dry_run",
    "-d",
    "--dry-run",
    is_flag=True,
    help="Show keys that would be deleted without deleting them",
)
@common_boto3_options
def delete_objects(bucket, keys, prefix, silent, dry_run, **boto_options):
    """
    Delete one or more object from an S3 bucket

    Pass one or more keys to delete them:

        s3-credentials delete-objects my-bucket one.txt two.txt

    To delete all files matching a prefix, pass --prefix:

        s3-credentials delete-objects my-bucket --prefix my-folder/
    """
    s3 = make_client("s3", **boto_options)
    if keys and prefix:
        raise click.ClickException("Cannot pass both keys and --prefix")
    if not keys and not prefix:
        raise click.ClickException("Specify one or more keys or use --prefix")
    if prefix:
        # List all keys with this prefix
        paginator = s3.get_paginator("list_objects_v2")
        response_iterator = paginator.paginate(Bucket=bucket, Prefix=prefix)
        keys = []
        for response in response_iterator:
            keys.extend([obj["Key"] for obj in response.get("Contents", [])])
    if not silent:
        click.echo(
            "Deleting {} object{} from {}".format(
                len(keys), "s" if len(keys) != 1 else "", bucket
            ),
            err=True,
        )
    if dry_run:
        click.echo("The following keys would be deleted:")
        for key in keys:
            click.echo(key)
        return
    for batch in batches(keys, 1000):
        # Remove any rogue \r characters:
        batch = [k.strip() for k in batch]
        response = s3.delete_objects(
            Bucket=bucket, Delete={"Objects": [{"Key": key} for key in batch]}
        )
        if response.get("Errors"):
            click.echo(
                "Errors deleting objects: {}".format(response["Errors"]), err=True
            )


@cli.command()
@click.argument("bucket", required=True)
@common_boto3_options
def get_public_access_block(bucket, **boto_options):
    """
    Get the public access settings for an S3 bucket

    Example usage:

        s3-credentials get-public-access-block my-bucket
    """
    s3 = make_client("s3", **boto_options)
    try:
        response = s3.get_public_access_block(Bucket=bucket)
    except botocore.exceptions.ClientError as e:
        raise click.ClickException(e)
    click.echo(json.dumps(response["PublicAccessBlockConfiguration"], indent=4))


@cli.command()
@click.argument("bucket", required=True)
@click.option(
    "--block-public-acls",
    type=bool,
    default=None,
    help="Block public ACLs for the bucket (true/false).",
)
@click.option(
    "--ignore-public-acls",
    type=bool,
    default=None,
    help="Ignore public ACLs for the bucket (true/false).",
)
@click.option(
    "--block-public-policy",
    type=bool,
    default=None,
    help="Block public bucket policies (true/false).",
)
@click.option(
    "--restrict-public-buckets",
    type=bool,
    default=None,
    help="Restrict public buckets (true/false).",
)
@click.option(
    "--allow-public-access",
    is_flag=True,
    help="Set all public access settings to false (allows full public access).",
)
@common_boto3_options
def set_public_access_block(
    bucket,
    block_public_acls,
    ignore_public_acls,
    block_public_policy,
    restrict_public_buckets,
    allow_public_access,
    **boto_options,
):
    """
    Configure public access settings for an S3 bucket.

    Example:

        s3-credentials set-public-access-block my-bucket --block-public-acls false

    To allow full public access to the bucket, use the --allow-public-access flag:

        s3-credentials set-public-access-block my-bucket --allow-public-access
    """
    s3 = make_client("s3", **boto_options)

    # Default public access block configuration
    public_access_block_config = {}

    if allow_public_access:
        # Set all settings to False if --allow-public-access is provided
        public_access_block_config = {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }
    else:
        # Add values only if they are explicitly provided
        if block_public_acls is not None:
            public_access_block_config["BlockPublicAcls"] = block_public_acls
        if ignore_public_acls is not None:
            public_access_block_config["IgnorePublicAcls"] = ignore_public_acls
        if block_public_policy is not None:
            public_access_block_config["BlockPublicPolicy"] = block_public_policy
        if restrict_public_buckets is not None:
            public_access_block_config["RestrictPublicBuckets"] = (
                restrict_public_buckets
            )

    if not public_access_block_config:
        raise click.ClickException(
            "No valid options provided. Use --help to see available options."
        )

    # Apply the public access block configuration to the bucket
    s3.put_public_access_block(
        Bucket=bucket, PublicAccessBlockConfiguration=public_access_block_config
    )

    click.echo(
        f"Updated public access block settings for bucket '{bucket}': {public_access_block_config}",
        err=True,
    )


def output(iterator, headers, nl, csv, tsv):
    if nl:
        for item in iterator:
            click.echo(json.dumps(item, default=str))
    elif csv or tsv:
        writer = DictWriter(
            sys.stdout, headers, dialect="excel-tab" if tsv else "excel"
        )
        writer.writeheader()
        writer.writerows(fix_json(row) for row in iterator)
    else:
        for line in stream_indented_json(iterator):
            click.echo(line)


def stream_indented_json(iterator, indent=2):
    # We have to iterate two-at-a-time so we can know if we
    # should output a trailing comma or if we have reached
    # the last item.
    current_iter, next_iter = itertools.tee(iterator, 2)
    next(next_iter, None)
    first = True
    for item, next_item in itertools.zip_longest(current_iter, next_iter):
        is_last = next_item is None
        data = item
        line = "{first}{serialized}{separator}{last}".format(
            first="[\n" if first else "",
            serialized=textwrap.indent(
                json.dumps(data, indent=indent, default=str), " " * indent
            ),
            separator="," if not is_last else "",
            last="\n]" if is_last else "",
        )
        yield line
        first = False
    if first:
        # We didn't output anything, so yield the empty list
        yield "[]"


def paginate(service, method, list_key, **kwargs):
    paginator = service.get_paginator(method)
    for response in paginator.paginate(**kwargs):
        yield from response.get(list_key) or []


def fix_json(row):
    # If a key value is list or dict, json encode it
    return dict(
        [
            (
                key,
                (
                    json.dumps(value, indent=2, default=str)
                    if isinstance(value, (dict, list, tuple))
                    else value
                ),
            )
            for key, value in row.items()
        ]
    )


def format_bytes(size):
    for x in ("bytes", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return "{:3.1f} {}".format(size, x)
        size /= 1024

    return size


def batches(all, batch_size):
    return [all[i : i + batch_size] for i in range(0, len(all), batch_size)]
