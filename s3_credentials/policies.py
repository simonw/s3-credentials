def read_write(bucket):
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_s3_rw-bucket.html
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": ["arn:aws:s3:::{}".format(bucket)],
            },
            {
                "Effect": "Allow",
                "Action": "s3:*Object",
                "Resource": ["arn:aws:s3:::{}/*".format(bucket)],
            },
        ],
    }


def read_only(bucket):
    return _policy(read_only_statements(bucket))


def read_only_statements(bucket):
    # https://github.com/simonw/s3-credentials/issues/23
    return [
        {
            "Effect": "Allow",
            "Action": ["s3:ListBucket"],
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
    return _policy(write_only_statements(bucket))


def write_only_statements(bucket):
    # https://github.com/simonw/s3-credentials/issues/25
    return [
        {
            "Effect": "Allow",
            "Action": ["s3:PutObject"],
            "Resource": ["arn:aws:s3:::{}/*".format(bucket)],
        }
    ]


def _policy(statements):
    return {"Version": "2012-10-17", "Statement": statements}
