# s3-credentials command help

This page shows the `--help` output for all of the `s3-credentials` commands.

<!-- [[[cog
import cog
from s3_credentials import cli
from click.testing import CliRunner
runner = CliRunner()
for command in (
    "",
    "create",
    "delete-user",
    "get-object",
    "list-bucket",
    "list-buckets",
    "list-roles",
    "list-user-policies",
    "list-users",
    "policy",
    "put-object",
    "whoami",
):
    result = runner.invoke(cli.cli, ([command] if command else []) + ["--help"])
    help = result.output.replace("Usage: cli", "Usage: s3-credentials")
    cog.out(
        "### s3-credentials {} --help\n\n```\n{}\n```\n".format(command, help.strip())
    )

]]] -->
### s3-credentials  --help

```
Usage: s3-credentials [OPTIONS] COMMAND [ARGS]...

  A tool for creating credentials for accessing S3 buckets

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.

Commands:
  create              Create and return new AWS credentials for specified...
  delete-user         Delete specified users, their access keys and their...
  get-object          Download an object from an S3 bucket
  list-bucket         List content of bucket
  list-buckets        List buckets - defaults to all, or pass one or more...
  list-roles          List all roles
  list-user-policies  List inline policies for specified user
  list-users          List all users
  policy              Generate JSON policy for one or more buckets
  put-object          Upload an object to an S3 bucket
  whoami              Identify currently authenticated user
```
### s3-credentials create --help

```
Usage: s3-credentials create [OPTIONS] BUCKETS...

  Create and return new AWS credentials for specified S3 buckets

Options:
  -f, --format [ini|json]         Output format for credentials
  -d, --duration DURATION         How long should these credentials work for?
                                  Default is forever, use 3600 for 3600 seconds,
                                  15m for 15 minutes, 1h for 1 hour
  --username TEXT                 Username to create or existing user to use
  -c, --create-bucket             Create buckets if they do not already exist
  --prefix TEXT                   Restrict to keys starting with this prefix
  --public                        Make the created bucket public: anyone will be
                                  able to download files if they know their name
  --read-only                     Only allow reading from the bucket
  --write-only                    Only allow writing to the bucket
  --policy POLICY                 Path to a policy.json file, or literal JSON
                                  string - $!BUCKET_NAME!$ will be replaced with
                                  the name of the bucket
  --bucket-region TEXT            Region in which to create buckets
  --silent                        Don't show performed steps
  --dry-run                       Show steps without executing them
  --user-permissions-boundary TEXT
                                  Custom permissions boundary to use for created
                                  users, or 'none' to create without. Defaults
                                  to limiting to S3 based on --read-only and
                                  --write-only options.
  --access-key TEXT               AWS access key ID
  --secret-key TEXT               AWS secret access key
  --session-token TEXT            AWS session token
  --endpoint-url TEXT             Custom endpoint URL
  -a, --auth FILENAME             Path to JSON/INI file containing credentials
  --help                          Show this message and exit.
```
### s3-credentials delete-user --help

```
Usage: s3-credentials delete-user [OPTIONS] USERNAMES...

  Delete specified users, their access keys and their inline policies

Options:
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
### s3-credentials get-object --help

```
Usage: s3-credentials get-object [OPTIONS] BUCKET KEY

  Download an object from an S3 bucket

Options:
  -o, --output FILE     Write to this file instead of stdout
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
### s3-credentials list-bucket --help

```
Usage: s3-credentials list-bucket [OPTIONS] BUCKET

  List content of bucket

Options:
  --prefix TEXT         List keys starting with this prefix
  --nl                  Output newline-delimited JSON
  --csv                 Output CSV
  --tsv                 Output TSV
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
### s3-credentials list-buckets --help

```
Usage: s3-credentials list-buckets [OPTIONS] [BUCKETS]...

  List buckets - defaults to all, or pass one or more bucket names

Options:
  --details             Include extra bucket details (slower)
  --nl                  Output newline-delimited JSON
  --csv                 Output CSV
  --tsv                 Output TSV
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
### s3-credentials list-roles --help

```
Usage: s3-credentials list-roles [OPTIONS] [ROLE_NAMES]...

  List all roles

Options:
  --details             Include attached policies (slower)
  --nl                  Output newline-delimited JSON
  --csv                 Output CSV
  --tsv                 Output TSV
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
### s3-credentials list-user-policies --help

```
Usage: s3-credentials list-user-policies [OPTIONS] [USERNAMES]...

  List inline policies for specified user

Options:
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
### s3-credentials list-users --help

```
Usage: s3-credentials list-users [OPTIONS]

  List all users

Options:
  --nl                  Output newline-delimited JSON
  --csv                 Output CSV
  --tsv                 Output TSV
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
### s3-credentials policy --help

```
Usage: s3-credentials policy [OPTIONS] BUCKETS...

  Generate JSON policy for one or more buckets

Options:
  --read-only      Only allow reading from the bucket
  --write-only     Only allow writing to the bucket
  --prefix TEXT    Restrict to keys starting with this prefix
  --public-bucket  Bucket policy for allowing public access
  --help           Show this message and exit.
```
### s3-credentials put-object --help

```
Usage: s3-credentials put-object [OPTIONS] BUCKET KEY PATH

  Upload an object to an S3 bucket

  To upload a file to /my-key.txt in the my-bucket bucket:

      s3-credentials put-object my-bucket my-key.txt /path/to/file.txt

  Use - to upload content from standard input:

      echo "Hello" | s3-credentials put-object my-bucket hello.txt -

Options:
  --content-type TEXT   Content-Type to use (default is auto-detected based on
                        file extension)
  -s, --silent          Don't show progress bar
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
### s3-credentials whoami --help

```
Usage: s3-credentials whoami [OPTIONS]

  Identify currently authenticated user

Options:
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
<!-- [[[end]]] -->