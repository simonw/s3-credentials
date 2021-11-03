from re import A
import boto3
import botocore
import click
import json
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


@cli.command()
@click.argument(
    "buckets",
    nargs=-1,
    required=True,
)
@click.option("--username", help="Username to create or existing user to use")
@click.option(
    "-c",
    "--create-bucket",
    help="Create buckets if they do not already exist",
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
    username,
    create_bucket,
    read_only,
    write_only,
    policy,
    bucket_region,
    user_permissions_boundary,
    silent,
    access_key,
    secret_key,
    session_token,
    endpoint_url,
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
    s3 = make_client("s3", access_key, secret_key, session_token, endpoint_url)
    iam = make_client("iam", access_key, secret_key, session_token, endpoint_url)
    # Verify buckets
    for bucket in buckets:
        # Create bucket if it doesn't exist
        if not bucket_exists(s3, bucket):
            if not create_bucket:
                raise click.ClickException(
                    "Bucket does not exist: {} - try --create-bucket to create it".format(
                        bucket
                    )
                )
            if create_bucket:
                kwargs = {}
                if bucket_region:
                    kwargs = {
                        "CreateBucketConfiguration": {
                            "LocationConstraint": bucket_region
                        }
                    }
                s3.create_bucket(Bucket=bucket, **kwargs)
                info = "Created bucket: {}".format(bucket)
                if bucket_region:
                    info += "in region: {}".format(bucket_region)
                log(info)
    # Buckets created - now create the user, if needed
    if not username:
        # Default username is "s3.read-write.bucket1,bucket2"
        username = "s3.{permission}.{buckets}".format(
            permission=permission, buckets=",".join(buckets)
        )
    if not user_exists(iam, username):
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
        iam.create_user(**kwargs)
        info = "Created user: {}".format(username)
        if user_permissions_boundary != "none":
            info += " with permissions boundary: {}".format(user_permissions_boundary)
        log(info)

    # Add inline policies to the user so they can access the buckets
    for bucket in buckets:
        policy_name = "s3.{permission}.{bucket}".format(
            permission=permission,
            bucket=bucket,
        )
        if policy:
            policy_dict = json.loads(policy.replace("$!BUCKET_NAME!$", bucket))
        else:
            if permission == "read-write":
                policy_dict = policies.read_write(bucket)
            elif permission == "read-only":
                policy_dict = policies.read_only(bucket)
            elif permission == "write-only":
                policy_dict = policies.write_only(bucket)
            else:
                assert False, "Unknown permission: {}".format(permission)
        iam.put_user_policy(
            PolicyDocument=json.dumps(policy_dict),
            PolicyName=policy_name,
            UserName=username,
        )
        log("Attached policy {} to user {}".format(policy_name, username))

    # Retrieve and print out the credentials
    response = iam.create_access_key(
        UserName=username,
    )
    log("Created access key for user: {}".format(username))
    click.echo(json.dumps(response["AccessKey"], indent=4, default=str))


@cli.command()
@common_boto3_options
def whoami(access_key, secret_key, session_token, endpoint_url):
    "Identify currently authenticated user"
    iam = make_client("iam", access_key, secret_key, session_token, endpoint_url)
    click.echo(json.dumps(iam.get_user()["User"], indent=4, default=str))


@cli.command()
@click.option("--array", help="Output a valid JSON array", is_flag=True)
@click.option("--nl", help="Output newline-delimited JSON", is_flag=True)
@common_boto3_options
def list_users(array, nl, access_key, secret_key, session_token, endpoint_url):
    "List all users"
    iam = make_client("iam", access_key, secret_key, session_token, endpoint_url)
    paginator = iam.get_paginator("list_users")
    gathered = []
    for response in paginator.paginate():
        for user in response["Users"]:
            if array:
                gathered.append(user)
            else:
                if nl:
                    click.echo(json.dumps(user, default=str))
                else:
                    click.echo(json.dumps(user, indent=4, default=str))
    if gathered:
        click.echo(json.dumps(gathered, indent=4, default=str))


@cli.command()
@click.argument("usernames", nargs=-1)
@common_boto3_options
def list_user_policies(usernames, access_key, secret_key, session_token, endpoint_url):
    "List inline policies for specified user"
    iam = make_client("iam", access_key, secret_key, session_token, endpoint_url)
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
@click.option("--array", help="Output a valid JSON array", is_flag=True)
@click.option("--nl", help="Output newline-delimited JSON", is_flag=True)
@common_boto3_options
def list_buckets(array, nl, access_key, secret_key, session_token, endpoint_url):
    "List all buckets"
    s3 = make_client("s3", access_key, secret_key, session_token, endpoint_url)
    gathered = []
    for bucket in s3.list_buckets()["Buckets"]:
        if array:
            gathered.append(bucket)
        else:
            if nl:
                click.echo(json.dumps(bucket, default=str))
            else:
                click.echo(json.dumps(bucket, indent=4, default=str))
    if gathered:
        click.echo(json.dumps(gathered, indent=4, default=str))


@cli.command()
@click.argument("usernames", nargs=-1, required=True)
@common_boto3_options
def delete_user(usernames, access_key, secret_key, session_token, endpoint_url):
    "Delete specified users, their access keys and their inline policies"
    iam = make_client("iam", access_key, secret_key, session_token, endpoint_url)
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


def make_client(service, access_key, secret_key, session_token, endpoint_url):
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
