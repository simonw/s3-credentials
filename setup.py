from setuptools import setup
import os

VERSION = "0.10"


def get_long_description():
    with open(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "README.md"),
        encoding="utf8",
    ) as fp:
        return fp.read()


setup(
    name="s3-credentials",
    description="A tool for creating credentials for accessing S3 buckets",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="Simon Willison",
    url="https://github.com/simonw/s3-credentials",
    project_urls={
        "Issues": "https://github.com/simonw/s3-credentials/issues",
        "CI": "https://github.com/simonw/s3-credentials/actions",
        "Changelog": "https://github.com/simonw/s3-credentials/releases",
    },
    license="Apache License, Version 2.0",
    version=VERSION,
    packages=["s3_credentials"],
    entry_points="""
        [console_scripts]
        s3-credentials=s3_credentials.cli:cli
    """,
    install_requires=["click", "boto3"],
    extras_require={"test": ["pytest", "pytest-mock", "cogapp"]},
    python_requires=">=3.6",
)
