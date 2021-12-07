def read_write(bucket):
    return wrap_policy(read_write_statements(bucket))


def read_write_statements(bucket):
    # https://github.com/simonw/s3-credentials/issues/24
    return read_only_statements(bucket) + [
        {
            "Effect": "Allow",
            "Action": ["s3:PutObject", "s3:DeleteObject"],
            "Resource": ["arn:aws:s3:::{}/*".format(bucket)],
        }
    ]


def read_only(bucket):
    return wrap_policy(read_only_statements(bucket))


def read_only_statements(bucket):
    # https://github.com/simonw/s3-credentials/issues/23
    return [
        {
            "Effect": "Allow",
            "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
            "Resource": ["arn:aws:s3:::{}".format(bucket)],
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:GetObjectAcl",
                "s3:GetObjectLegalHold",
                "s3:GetObjectRetention",
                "s3:GetObjectTagging",
            ],
            "Resource": ["arn:aws:s3:::{}/*".format(bucket)],
        },
    ]


def write_only(bucket):
    return wrap_policy(write_only_statements(bucket))


def write_only_statements(bucket):
    # https://github.com/simonw/s3-credentials/issues/25
    return [
        {
            "Effect": "Allow",
            "Action": ["s3:PutObject"],
            "Resource": ["arn:aws:s3:::{}/*".format(bucket)],
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
