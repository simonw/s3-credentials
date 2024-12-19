# Command help

This page shows the `--help` output for all of the `s3-credentials` commands.

<!-- [[[cog
import cog
from s3_credentials import cli
from click.testing import CliRunner
runner = CliRunner()
# Get a list of all the commands
result = runner.invoke(cli.cli, ["--help"])
lines = result.output.split("Commands:")[1].strip().split("\n")
commands = [l.strip().split()[0] for l in lines if l]
for command in [""] + commands:
    result = runner.invoke(cli.cli, ([command] if command else []) + ["--help"])
    help = result.output.replace("Usage: cli", "Usage: s3-credentials")
    cog.out(
        "## s3-credentials {} --help\n\n```\n{}\n```\n".format(command, help.strip())
    )

]]] -->
## s3-credentials  --help

```
Usage: s3-credentials [OPTIONS] COMMAND [ARGS]...

  A tool for creating credentials for accessing S3 buckets

  Documentation: https://s3-credentials.readthedocs.io/

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.

Commands:
  create              Create and return new AWS credentials for specified...
  debug-bucket        Run a bunch of diagnostics to help debug a bucket
  delete-objects      Delete one or more object from an S3 bucket
  delete-user         Delete specified users, their access keys and their...
  get-bucket-policy   Get bucket policy for a bucket
  get-cors-policy     Get CORS policy for a bucket
  get-object          Download an object from an S3 bucket
  get-objects         Download multiple objects from an S3 bucket
  list-bucket         List contents of bucket
  list-buckets        List buckets
  list-roles          List roles
  list-user-policies  List inline policies for specified users
  list-users          List all users for this account
  policy              Output generated JSON policy for one or more buckets
  put-object          Upload an object to an S3 bucket
  put-objects         Upload multiple objects to an S3 bucket
  set-bucket-policy   Set bucket policy for a bucket
  set-cors-policy     Set CORS policy for a bucket
  whoami              Identify currently authenticated user
```
## s3-credentials create --help

```
Usage: s3-credentials create [OPTIONS] BUCKETS...

  Create and return new AWS credentials for specified S3 buckets - optionally
  also creating the bucket if it does not yet exist.

  To create a new bucket and output read-write credentials:

      s3-credentials create my-new-bucket -c

  To create read-only credentials for an existing bucket:

      s3-credentials create my-existing-bucket --read-only

  To create write-only credentials that are only valid for 15 minutes:

      s3-credentials create my-existing-bucket --write-only -d 15m

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
  --website                       Configure bucket to act as a website, using
                                  index.html and error.html
  --read-only                     Only allow reading from the bucket
  --write-only                    Only allow writing to the bucket
  --policy POLICY                 Path to a policy.json file, or literal JSON
                                  string - $!BUCKET_NAME!$ will be replaced with
                                  the name of the bucket
  --statement STATEMENT           JSON statement to add to the policy
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
## s3-credentials debug-bucket --help

```
Usage: s3-credentials debug-bucket [OPTIONS] BUCKET

  Run a bunch of diagnostics to help debug a bucket

     s3-credentials debug-bucket my-bucket

Options:
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
## s3-credentials delete-objects --help

```
Usage: s3-credentials delete-objects [OPTIONS] BUCKET [KEYS]...

  Delete one or more object from an S3 bucket

  Pass one or more keys to delete them:

      s3-credentials delete-objects my-bucket one.txt two.txt

  To delete all files matching a prefix, pass --prefix:

      s3-credentials delete-objects my-bucket --prefix my-folder/

Options:
  --prefix TEXT         Delete everything with this prefix
  -s, --silent          Don't show informational output
  -d, --dry-run         Show keys that would be deleted without deleting them
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
## s3-credentials delete-user --help

```
Usage: s3-credentials delete-user [OPTIONS] USERNAMES...

  Delete specified users, their access keys and their inline policies

      s3-credentials delete-user username1 username2

Options:
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
## s3-credentials get-bucket-policy --help

```
Usage: s3-credentials get-bucket-policy [OPTIONS] BUCKET

  Get bucket policy for a bucket

     s3-credentials get-bucket-policy my-bucket

  Returns the bucket policy for this bucket, if set, as JSON

Options:
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
## s3-credentials get-cors-policy --help

```
Usage: s3-credentials get-cors-policy [OPTIONS] BUCKET

  Get CORS policy for a bucket

     s3-credentials get-cors-policy my-bucket

  Returns the CORS policy for this bucket, if set, as JSON

Options:
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
## s3-credentials get-object --help

```
Usage: s3-credentials get-object [OPTIONS] BUCKET KEY

  Download an object from an S3 bucket

  To see the contents of the bucket on standard output:

      s3-credentials get-object my-bucket hello.txt

  To save to a file:

      s3-credentials get-object my-bucket hello.txt -o hello.txt

Options:
  -o, --output FILE     Write to this file instead of stdout
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
## s3-credentials get-objects --help

```
Usage: s3-credentials get-objects [OPTIONS] BUCKET [KEYS]...

  Download multiple objects from an S3 bucket

  To download everything, run:

      s3-credentials get-objects my-bucket

  Files will be saved to a directory called my-bucket. Use -o dirname to save to
  a different directory.

  To download specific keys, list them:

      s3-credentials get-objects my-bucket one.txt path/two.txt

  To download files matching a glob-style pattern, use:

      s3-credentials get-objects my-bucket --pattern '*/*.js'

Options:
  -o, --output DIRECTORY  Write to this directory instead of one matching the
                          bucket name
  -p, --pattern TEXT      Glob patterns for files to download, e.g. '*/*.js'
  -s, --silent            Don't show progress bar
  --access-key TEXT       AWS access key ID
  --secret-key TEXT       AWS secret access key
  --session-token TEXT    AWS session token
  --endpoint-url TEXT     Custom endpoint URL
  -a, --auth FILENAME     Path to JSON/INI file containing credentials
  --help                  Show this message and exit.
```
## s3-credentials list-bucket --help

```
Usage: s3-credentials list-bucket [OPTIONS] BUCKET

  List contents of bucket

  To list the contents of a bucket as JSON:

      s3-credentials list-bucket my-bucket

  Add --csv or --csv for CSV or TSV format:

      s3-credentials list-bucket my-bucket --csv

  Add --urls to get an extra URL field for each key:

      s3-credentials list-bucket my-bucket --urls

Options:
  --prefix TEXT         List keys starting with this prefix
  --urls                Show URLs for each key
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
## s3-credentials list-buckets --help

```
Usage: s3-credentials list-buckets [OPTIONS] [BUCKETS]...

  List buckets

  To list all buckets and their creation time as JSON:

      s3-credentials list-buckets

  Add --csv or --csv for CSV or TSV format:

      s3-credentials list-buckets --csv

  For extra details per bucket (much slower) add --details

      s3-credentials list-buckets --details

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
## s3-credentials list-roles --help

```
Usage: s3-credentials list-roles [OPTIONS] [ROLE_NAMES]...

  List roles

  To list all roles for this AWS account:

      s3-credentials list-roles

  Add --csv or --csv for CSV or TSV format:

      s3-credentials list-roles --csv

  For extra details per role (much slower) add --details

      s3-credentials list-roles --details

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
## s3-credentials list-user-policies --help

```
Usage: s3-credentials list-user-policies [OPTIONS] [USERNAMES]...

  List inline policies for specified users

      s3-credentials list-user-policies username

  Returns policies for all users if no usernames are provided.

Options:
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
## s3-credentials list-users --help

```
Usage: s3-credentials list-users [OPTIONS]

  List all users for this account

      s3-credentials list-users

  Add --csv or --csv for CSV or TSV format:

      s3-credentials list-users --csv

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
## s3-credentials policy --help

```
Usage: s3-credentials policy [OPTIONS] BUCKETS...

  Output generated JSON policy for one or more buckets

  Takes the same options as s3-credentials create

  To output a read-only JSON policy for a bucket:

      s3-credentials policy my-bucket --read-only

Options:
  --read-only            Only allow reading from the bucket
  --write-only           Only allow writing to the bucket
  --prefix TEXT          Restrict to keys starting with this prefix
  --statement STATEMENT  JSON statement to add to the policy
  --public-bucket        Bucket policy for allowing public access
  --help                 Show this message and exit.
```
## s3-credentials put-object --help

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
## s3-credentials put-objects --help

```
Usage: s3-credentials put-objects [OPTIONS] BUCKET OBJECTS...

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

Options:
  --prefix TEXT         Prefix to add to the files within the bucket
  -s, --silent          Don't show progress bar
  --dry-run             Show steps without executing them
  --access-key TEXT     AWS access key ID
  --secret-key TEXT     AWS secret access key
  --session-token TEXT  AWS session token
  --endpoint-url TEXT   Custom endpoint URL
  -a, --auth FILENAME   Path to JSON/INI file containing credentials
  --help                Show this message and exit.
```
## s3-credentials set-bucket-policy --help

```
Usage: s3-credentials set-bucket-policy [OPTIONS] BUCKET

  Set bucket policy for a bucket

      s3-credentials set-bucket-policy my-bucket --policy-file policy.json

  Or to set a policy that allows GET requests from all:

      s3-credentials set-bucket-policy my-bucket --allow-all-get

Options:
  --policy-file FILENAME
  --allow-all-get         Allow GET requests from all
  --access-key TEXT       AWS access key ID
  --secret-key TEXT       AWS secret access key
  --session-token TEXT    AWS session token
  --endpoint-url TEXT     Custom endpoint URL
  -a, --auth FILENAME     Path to JSON/INI file containing credentials
  --help                  Show this message and exit.
```
## s3-credentials set-cors-policy --help

```
Usage: s3-credentials set-cors-policy [OPTIONS] BUCKET

  Set CORS policy for a bucket

  To allow GET requests from any origin:

      s3-credentials set-cors-policy my-bucket

  To allow GET and PUT from a specific origin and expose ETag headers:

      s3-credentials set-cors-policy my-bucket \
        --allowed-method GET \
        --allowed-method PUT \
        --allowed-origin https://www.example.com/ \
        --expose-header ETag

Options:
  -m, --allowed-method TEXT  Allowed method e.g. GET
  -h, --allowed-header TEXT  Allowed header e.g. Authorization
  -o, --allowed-origin TEXT  Allowed origin e.g. https://www.example.com/
  -e, --expose-header TEXT   Header to expose e.g. ETag
  --max-age-seconds INTEGER  How long to cache preflight requests
  --access-key TEXT          AWS access key ID
  --secret-key TEXT          AWS secret access key
  --session-token TEXT       AWS session token
  --endpoint-url TEXT        Custom endpoint URL
  -a, --auth FILENAME        Path to JSON/INI file containing credentials
  --help                     Show this message and exit.
```
## s3-credentials whoami --help

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
