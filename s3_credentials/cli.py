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
