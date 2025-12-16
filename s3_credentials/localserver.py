"""
Local server for serving S3 credentials via HTTP.
"""
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import threading
import time

import click

from . import policies


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


class CredentialCache:
    """Thread-safe credential cache that regenerates credentials on expiry."""

    def __init__(
        self, iam, sts, bucket, permission, prefix, duration, extra_statements
    ):
        self.iam = iam
        self.sts = sts
        self.bucket = bucket
        self.permission = permission
        self.prefix = prefix
        self.duration = duration
        self.extra_statements = extra_statements
        self._credentials = None
        self._expiry_time = None
        self._lock = threading.Lock()
        self._generating = False

    def _generate_policy(self):
        """Generate the IAM policy for bucket access."""
        statements = []
        if self.permission == "read-write":
            statements.extend(policies.read_write_statements(self.bucket, self.prefix))
        elif self.permission == "read-only":
            statements.extend(policies.read_only_statements(self.bucket, self.prefix))
        elif self.permission == "write-only":
            statements.extend(policies.write_only_statements(self.bucket, self.prefix))
        if self.extra_statements:
            statements.extend(self.extra_statements)
        return policies.wrap_policy(statements)

    def _generate_credentials(self):
        """Generate new temporary credentials using STS assume_role."""
        s3_role_arn = ensure_s3_role_exists(self.iam, self.sts)

        policy_document = self._generate_policy()
        credentials_response = self.sts.assume_role(
            RoleArn=s3_role_arn,
            RoleSessionName="s3.{permission}.{bucket}".format(
                permission=self.permission,
                bucket=self.bucket,
            ),
            Policy=json.dumps(policy_document),
            DurationSeconds=self.duration,
        )
        return credentials_response["Credentials"]

    def get_credentials(self):
        """Get cached credentials, regenerating if expired or about to expire."""
        current_time = time.time()

        # Check if we need new credentials
        with self._lock:
            if self._credentials is not None and self._expiry_time is not None:
                # Return cached credentials if still valid
                if current_time < self._expiry_time:
                    return self._credentials

            # Need to generate new credentials
            # Check if another thread is already generating
            if self._generating:
                # Wait for the other thread to finish
                while self._generating:
                    self._lock.release()
                    time.sleep(0.1)
                    self._lock.acquire()
                return self._credentials

            # Mark that we're generating
            self._generating = True

        try:
            # Generate new credentials outside the lock
            credentials = self._generate_credentials()
            with self._lock:
                self._credentials = credentials
                # Set expiry time to duration from now
                self._expiry_time = current_time + self.duration
                self._generating = False
            return credentials
        except Exception:
            with self._lock:
                self._generating = False
            raise


def make_credential_handler(credential_cache):
    """Create an HTTP request handler class with access to the credential cache."""

    class CredentialHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            # Log to stderr with timestamp
            click.echo(
                "{} - {}".format(
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    format % args,
                ),
                err=True,
            )

        def do_GET(self):
            if self.path != "/":
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Not found"}).encode())
                return

            try:
                credentials = credential_cache.get_credentials()
                response_data = {
                    "Version": 1,
                    "AccessKeyId": credentials["AccessKeyId"],
                    "SecretAccessKey": credentials["SecretAccessKey"],
                    "SessionToken": credentials["SessionToken"],
                    "Expiration": (
                        credentials["Expiration"].isoformat()
                        if hasattr(credentials["Expiration"], "isoformat")
                        else str(credentials["Expiration"])
                    ),
                }
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(response_data, indent=2).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())

    return CredentialHandler


def run_server(
    bucket,
    port,
    host,
    permission,
    prefix,
    duration,
    extra_statements,
    iam,
    sts,
):
    """Run the credential server."""
    # Create credential cache
    credential_cache = CredentialCache(
        iam=iam,
        sts=sts,
        bucket=bucket,
        permission=permission,
        prefix=prefix,
        duration=duration,
        extra_statements=extra_statements,
    )

    # Pre-generate credentials to catch any errors early
    click.echo("Generating initial credentials...", err=True)
    credential_cache.get_credentials()

    # Create and start server
    handler = make_credential_handler(credential_cache)
    server = HTTPServer((host, port), handler)

    click.echo(
        "Serving {} credentials for bucket '{}' at http://{}:{}/".format(
            permission, bucket, host, port
        ),
        err=True,
    )
    click.echo("Duration: {} seconds".format(duration), err=True)
    click.echo("Press Ctrl+C to stop", err=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        click.echo("\nShutting down server...", err=True)
        server.shutdown()
