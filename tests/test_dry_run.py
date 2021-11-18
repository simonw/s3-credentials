from click.testing import CliRunner
from s3_credentials.cli import cli
import pytest
import re
import textwrap


def assert_match_with_wildcards(pattern, input):
    # Pattern language is simple: '*' becomes '*?'
    bits = pattern.split("*")
    regex = "^{}$".format(".*?".join(re.escape(bit) for bit in bits))
    print(regex)
    match = re.compile(regex.strip(), re.DOTALL).match(input.strip())
    if match is None:
        # Build a useful message
        message = "Pattern:\n{}\n\nDoes not match input:\n\n{}".format(pattern, input)
        bad_bits = [bit for bit in bits if bit not in input]
        if bad_bits:
            message += "\nThese parts were not found in the input:\n\n"
            for bit in bad_bits:
                message += textwrap.indent("{}\n\n".format(bit), "    ")
        assert False, message


@pytest.mark.parametrize(
    "options,expected",
    (
        (
            [],
            (
                """Would create bucket: 'my-bucket'
Would create user: 's3.read-write.my-bucket' with permissions boundary: 'arn:aws:iam::aws:policy/AmazonS3FullAccess'
Would attach policy called 's3.read-write.my-bucket' to user 's3.read-write.my-bucket', details:*
Would call create access key for user 's3.read-write.my-bucket'"""
            ),
        ),
        (
            ["--username", "frank"],
            (
                """Would create bucket: 'my-bucket'
Would create user: 'frank' with permissions boundary: 'arn:aws:iam::aws:policy/AmazonS3FullAccess'
Would attach policy called 's3.read-write.my-bucket' to user 'frank', details:*
Would call create access key for user 'frank'"""
            ),
        ),
        (
            ["--duration", "20m"],
            (
                """Would create bucket: 'my-bucket'
Would ensure role: 's3-credentials.AmazonS3FullAccess'
Would assume role using following policy for 1200 seconds:*"""
            ),
        ),
    ),
)
def test_dry_run(options, expected):
    runner = CliRunner()
    result = runner.invoke(cli, ["create", "my-bucket", "--dry-run"] + options)
    assert result.exit_code == 0, result.output
    assert_match_with_wildcards(expected, result.output)
