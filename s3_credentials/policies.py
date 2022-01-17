def read_write(bucket, prefix="*"):
    return wrap_policy(read_write_statements(bucket, prefix=prefix))


def read_write_statements(bucket, prefix="*"):
    # https://github.com/simonw/s3-credentials/issues/24
    if not prefix.endswith("*"):
        prefix += "*"
    return read_only_statements(bucket, prefix) + [
        {
            "Effect": "Allow",
            "Action": ["s3:PutObject", "s3:DeleteObject"],
            "Resource": ["arn:aws:s3:::{}/{}".format(bucket, prefix)],
        }
    ]


def read_only(bucket, prefix="*"):
    return wrap_policy(read_only_statements(bucket, prefix))


def read_only_statements(bucket, prefix="*"):
    # https://github.com/simonw/s3-credentials/issues/23
    statements = []
    if not prefix.endswith("*"):
        prefix += "*"
    if prefix != "*":
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
                        "s3:prefix": [prefix]
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
            "Resource": ["arn:aws:s3:::{}/{}".format(bucket, prefix)],
        },
    ]


def write_only(bucket, prefix="*"):
    return wrap_policy(write_only_statements(bucket, prefix))


def write_only_statements(bucket, prefix="*"):
    # https://github.com/simonw/s3-credentials/issues/25
    if not prefix.endswith("*"):
        prefix += "*"
    return [
        {
            "Effect": "Allow",
            "Action": ["s3:PutObject"],
            "Resource": ["arn:aws:s3:::{}/{}".format(bucket, prefix)],
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
