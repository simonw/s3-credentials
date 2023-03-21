# Configuration

This tool uses [boto3](https://boto3.amazonaws.com/) under the hood which supports [a number of different ways](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html) of providing your AWS credentials.

If you have an existing `~/.aws/config` or `~/.aws/credentials` file the tool will use that.

One way to create those files is using the `aws configure` command, available if you first run `pip install awscli`.

Alternatively, you can set the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables before calling this tool.

You can also use the `--access-key=`, `--secret-key=`, `--session-token` and `--auth` options documented below.

## Common command options

All of the `s3-credentials` commands also accept the following options for authenticating against AWS:

- `--access-key`: AWS access key ID
- `--secret-key`: AWS secret access key
- `--session-token`: AWS session token
- `--endpoint-url`: Custom endpoint URL
- `--auth`: file (or `-` for standard input) containing credentials to use

The file passed to `--auth` can be either a JSON file or an INI file. JSON files should contain the following:

```json
{
    "AccessKeyId": "AKIAWXFXAIOZA5IR5PY4",
    "SecretAccessKey": "g63..."
}
```
The JSON file can also optionally include a session token in a `"SessionToken"` key.

The INI format variant of this file should look like this:

```ini
[default]
aws_access_key_id=AKIAWXFXAIOZNCR2ST7S
aws_secret_access_key=g63...
```
Any section headers will do - the tool will use the information from the first section it finds in the file which has a `aws_access_key_id` key.

These auth file formats are the same as those that can be created using the `create` command.
