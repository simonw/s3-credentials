# Contributing

To contribute to this tool, first checkout [the code](https://github.com/simonw/s3-credentials). You can run the tests locally using `pytest` and `uv`:

    cd s3-credentials
    uv run pytest

Any changes to the generated policies require an update to the docs using [Cog](https://github.com/nedbat/cog):

    uv run poe cog

To preview the documentation locally, you can use:

    uv run poe livehtml

## Integration tests

The main tests all use stubbed interfaces to AWS, so will not make any outbound API calls.

There is also a suite of integration tests in `tests/test_integration.py` which DO make API calls to AWS, using credentials from your environment variables or `~/.aws/credentials` file.

These tests are skipped by default. If you have AWS configured with an account that has permission to run the actions required by `s3-credentials` (create users, roles, buckets etc) you can run these tests using:

    uv run pytest --integration

The tests will create a number of different users and buckets and should then delete them once they finish running.
