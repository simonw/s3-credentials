import boto3
import click
import json


@click.group()
@click.version_option()
def cli():
    "A tool for creating credentials for accessing S3 buckets"


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
