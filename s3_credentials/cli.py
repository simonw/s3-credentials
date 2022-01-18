from re import A
import boto3
import botocore
import click
import configparser
from csv import DictWriter
import io
import itertools
import json
import mimetypes
import os
import re
import sys
import textwrap
from . import policies


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
    "A tool for creating credentials for accessing S3 buckets"


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
    "--public-bucket",
    help="Bucket policy for allowing public access",
    is_flag=True,
)
def policy(buckets, read_only, write_only, prefix, public_bucket):
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
@click.option("--read-only", help="Only allow reading from the bucket", is_flag=True)
@click.option("--write-only", help="Only allow writing to the bucket", is_flag=True)
@click.option(
    "--policy",
    type=PolicyParam(),
    help="Path to a policy.json file, or literal JSON string - $!BUCKET_NAME!$ will be replaced with the name of the bucket",
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
    read_only,
    write_only,
    policy,
    bucket_region,
    user_permissions_boundary,
    silent,
    dry_run,
    **boto_options
):
    "Create and return new AWS credentials for specified S3 buckets"
    if read_only and write_only:
        raise click.ClickException(
            "Cannot use --read-only and --write-only at the same time"
        )

    def log(message):
        if not silent:
            click.echo(message, err=True)

    permission = "read-write"
    if read_only:
        permission = "read-only"
    if write_only:
        permission = "write-only"

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
                    if bucket_policy:
                        click.echo("... then attach the following bucket policy to it:")
                        click.echo(json.dumps(bucket_policy, indent=4))
                else:
                    s3.create_bucket(Bucket=bucket, **kwargs)
                    info = "Created bucket: {}".format(bucket)
                    if bucket_region:
                        info += " in region: {}".format(bucket_region)
                    log(info)

                    if bucket_policy:
                        s3.put_bucket_policy(
                            Bucket=bucket, Policy=json.dumps(bucket_policy)
                        )
                        log("Attached bucket policy allowing public access")
    # At this point the buckets definitely exist - create the inline policy for assume_role()
    assume_role_policy = {}
    bucket_access_policy = {}
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
                    permission="custom" if policy else permission,
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
            permission="custom" if policy else permission, buckets=",".join(buckets)
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
            permission="custom" if policy else permission,
            bucket=bucket,
        )
        if policy:
            user_policy = json.loads(policy.replace("$!BUCKET_NAME!$", bucket))
        else:
            if permission == "read-write":
                user_policy = policies.read_write(bucket, prefix)
            elif permission == "read-only":
                user_policy = policies.read_only(bucket, prefix)
            elif permission == "write-only":
                user_policy = policies.write_only(bucket, prefix)
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
    "List all users"
    iam = make_client("iam", **boto_options)
    paginator = iam.get_paginator("list_users")
    gathered = []

    def iterate():
        for response in paginator.paginate():
            for user in response["Users"]:
                yield user

    output(
        iterate(),
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
@click.argument("usernames", nargs=-1)
@common_boto3_options
def list_user_policies(usernames, **boto_options):
    "List inline policies for specified user"
    iam = make_client("iam", **boto_options)
    if not usernames:
        usernames = []
        paginator = iam.get_paginator("list_users")
        for response in paginator.paginate():
            for user in response["Users"]:
                usernames.append(user["UserName"])

    paginator = iam.get_paginator("list_user_policies")
    for username in usernames:
        click.echo("User: {}".format(username))
        for response in paginator.paginate(UserName=username):
            for policy_name in response["PolicyNames"]:
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
    "List buckets - defaults to all, or pass one or more bucket names"
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
                except s3.exceptions.ClientError:
                    bucket_website = None
                bucket["bucket_acl"] = bucket_acl
                bucket["public_access_block"] = pab
                bucket["bucket_website"] = bucket_website
            yield bucket

    output(iterator(), headers, nl, csv, tsv)


@cli.command()
@click.argument("usernames", nargs=-1, required=True)
@common_boto3_options
def delete_user(usernames, **boto_options):
    "Delete specified users, their access keys and their inline policies"
    iam = make_client("iam", **boto_options)
    policy_paginator = iam.get_paginator("list_user_policies")
    access_key_paginator = iam.get_paginator("list_access_keys")
    for username in usernames:
        click.echo("User: {}".format(username))
        # Fetch and delete their policies
        policy_names = []
        for response in policy_paginator.paginate(UserName=username):
            for policy_name in response["PolicyNames"]:
                policy_names.append(policy_name)
        for policy_name in policy_names:
            iam.delete_user_policy(
                UserName=username,
                PolicyName=policy_name,
            )
            click.echo("  Deleted policy: {}".format(policy_name))
        # Fetch and delete their access keys
        access_key_ids = []
        for response in access_key_paginator.paginate(UserName=username):
            for access_key in response["AccessKeyMetadata"]:
                access_key_ids.append(access_key["AccessKeyId"])
        for access_key_id in access_key_ids:
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
                            "Condition": {},
                        }
                    ],
                }
            ),
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
@common_output_options
@common_boto3_options
def list_bucket(bucket, prefix, nl, csv, tsv, **boto_options):
    "List content of bucket"
    s3 = make_client("s3", **boto_options)
    paginator = s3.get_paginator("list_objects_v2")
    kwargs = {"Bucket": bucket}
    if prefix:
        kwargs["Prefix"] = prefix

    def iterate():
        try:
            for page in paginator.paginate(**kwargs):
                for row in page["Contents"]:
                    yield row
        except botocore.exceptions.ClientError as e:
            raise click.ClickException(e)

    output(
        iterate(),
        ("Key", "LastModified", "ETag", "Size", "StorageClass", "Owner"),
        nl,
        csv,
        tsv,
    )


@cli.command()
@click.argument("bucket")
@click.argument("key")
@click.argument(
    "content",
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
def put_object(bucket, key, content, content_type, silent, **boto_options):
    "Upload an object to an S3 bucket"
    s3 = make_client("s3", **boto_options)
    size = None
    extra_args = {}
    if content == "-":
        # boto needs to be able to seek
        fp = io.BytesIO(sys.stdin.buffer.read())
        if not silent:
            size = fp.getbuffer().nbytes
    else:
        if not content_type:
            content_type = mimetypes.guess_type(content)[0]
        fp = click.open_file(content, "rb")
        if not silent:
            size = os.path.getsize(content)
    if content_type is not None:
        extra_args["ContentType"] = content_type
    if not silent:
        # Show progress bar
        with click.progressbar(length=size, label="Uploading") as bar:
            s3.upload_fileobj(
                fp, bucket, key, Callback=bar.update, ExtraArgs=extra_args
            )
    else:
        s3.upload_fileobj(fp, bucket, key, ExtraArgs=extra_args)


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
    "Download an object from an S3 bucket"
    s3 = make_client("s3", **boto_options)
    if not output:
        fp = sys.stdout.buffer
    else:
        fp = click.open_file(output, "wb")
    s3.download_fileobj(bucket, key, fp)


def output(iterator, headers, nl, csv, tsv):
    if nl:
        for item in iterator:
            click.echo(json.dumps(item, default=str))
    elif csv or tsv:
        writer = DictWriter(
            sys.stdout, headers, dialect="excel-tab" if tsv else "excel"
        )
        writer.writeheader()
        writer.writerows(iterator)
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
