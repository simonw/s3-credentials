def _normalize_prefixes(prefix):
    if isinstance(prefix, str):
        prefixes = [prefix]
    elif prefix is None:
        prefixes = ["*"]
    else:
        prefixes = list(prefix)
    if not prefixes:
        prefixes = ["*"]
    return [p + "*" if not p.endswith("*") else p for p in prefixes]


def read_write(bucket, prefix="*", extra_statements=None):
    statements = read_write_statements(bucket, prefix=prefix)
    if extra_statements:
        statements.extend(extra_statements)
    return wrap_policy(statements)


def read_write_statements(bucket, prefix="*"):
    # https://github.com/simonw/s3-credentials/issues/24
    prefixes = _normalize_prefixes(prefix)
    return read_only_statements(bucket, prefixes) + [
        {
            "Effect": "Allow",
            "Action": ["s3:PutObject", "s3:DeleteObject"],
            "Resource": ["arn:aws:s3:::{}/{}".format(bucket, p) for p in prefixes],
        }
    ]


def read_only(bucket, prefix="*", extra_statements=None):
    statements = read_only_statements(bucket, prefix=prefix)
    if extra_statements:
        statements.extend(extra_statements)
    return wrap_policy(statements)


def read_only_statements(bucket, prefix="*"):
    # https://github.com/simonw/s3-credentials/issues/23
    statements = []
    prefixes = _normalize_prefixes(prefix)
    if prefixes != ["*"]:
        statements.append(
            {
                "Effect": "Allow",
                "Action": ["s3:GetBucketLocation"],
                "Resource": ["arn:aws:s3:::{}".format(bucket)],
            }
        )
        statements.append(
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": ["arn:aws:s3:::{}".format(bucket)],
                "Condition": {
                    "StringLike": {
                        # Note that prefix must end in / if user wants to limit to a folder
                        "s3:prefix": prefixes
                    }
                },
            }
        )
    else:
        # We can combine s3:GetBucketLocation and s3:ListBucket into one
        statements.append(
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": ["arn:aws:s3:::{}".format(bucket)],
            }
        )

    return statements + [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:GetObjectAcl",
                "s3:GetObjectLegalHold",
                "s3:GetObjectRetention",
                "s3:GetObjectTagging",
            ],
            "Resource": ["arn:aws:s3:::{}/{}".format(bucket, p) for p in prefixes],
        },
    ]


def write_only(bucket, prefix="*", extra_statements=None):
    statements = write_only_statements(bucket, prefix=prefix)
    if extra_statements:
        statements.extend(extra_statements)
    return wrap_policy(statements)


def write_only_statements(bucket, prefix="*"):
    # https://github.com/simonw/s3-credentials/issues/25
    prefixes = _normalize_prefixes(prefix)
    return [
        {
            "Effect": "Allow",
            "Action": ["s3:PutObject"],
            "Resource": ["arn:aws:s3:::{}/{}".format(bucket, p) for p in prefixes],
        }
    ]


def wrap_policy(statements):
    return {"Version": "2012-10-17", "Statement": statements}


def bucket_policy_allow_all_get(bucket):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAllGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::{}/*".format(bucket)],
            }
        ],
    }
