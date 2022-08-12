# Contributing

To contribute to this tool, first checkout [the code](https://github.com/simonw/s3-credentials). Then create a new virtual environment:

    cd s3-credentials
    python -m venv venv
    source venv/bin/activate

Or if you are using `pipenv`:

    pipenv shell

Now install the dependencies and test dependencies:

    pip install -e '.[test]'

To run the tests:

    pytest

Any changes to the generated policies require an update to the README using [Cog](https://github.com/nedbat/cog):

    cog -r README.md

## Integration tests

The main tests all use stubbed interfaces to AWS, so will not make any outbound API calls.

There is also a suite of integration tests in `tests/test_integration.py` which DO make API calls to AWS, using credentials from your environment variables or `~/.aws/credentials` file.

These tests are skipped by default. If you have AWS configured with an account that has permission to run the actions required by `s3-credentials` (create users, roles, buckets etc) you can run these tests using:

    pytest --integration

The tests will create a number of different users and buckets and should then delete them once they finish running.
