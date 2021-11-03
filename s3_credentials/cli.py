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


@click.group()
@click.version_option()
def cli():
    "A tool for creating credentials for accessing S3 buckets"


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
def create(
    buckets,
    username,
    create_bucket,
    read_only,
    write_only,
    bucket_region,
    user_permissions_boundary,
    silent,
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
    s3 = boto3.client("s3")
    iam = boto3.client("iam")
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
        policy = {}
        if permission == "read-write":
            policy = policies.read_write(bucket)
        elif permission == "read-only":
            policy = policies.read_only(bucket)
        elif permission == "write-only":
            policy = policies.write_only(bucket)
        else:
            assert False, "Unknown permission: {}".format(permission)
        iam.put_user_policy(
            PolicyDocument=json.dumps(policy),
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
def whoami():
    "Identify currently authenticated user"
    iam = boto3.client("iam")
    click.echo(json.dumps(iam.get_user()["User"], indent=4, default=str))


@cli.command()
@click.option("--array", help="Output a valid JSON array", is_flag=True)
@click.option("--nl", help="Output newline-delimited JSON", is_flag=True)
def list_users(array, nl):
    "List all users"
    iam = boto3.client("iam")
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
def list_user_policies(usernames):
    "List inline policies for specified user"
    iam = boto3.client("iam")
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
def list_buckets(array, nl):
    "List all buckets"
    s3 = boto3.client("s3")
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
