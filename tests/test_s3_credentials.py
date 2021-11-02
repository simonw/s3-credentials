from click.testing import CliRunner
from s3_credentials.cli import cli
import json


def test_whoami(mocker):
    boto3 = mocker.patch("boto3.client")
    boto3().get_user.return_value = {"User": {"username": "name"}}
    boto3.get_user().return_value = {"User": "blah"}
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["whoami"])
        assert result.exit_code == 0
        assert json.loads(result.output) == {"username": "name"}
