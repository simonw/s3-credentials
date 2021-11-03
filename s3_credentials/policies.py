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
                "Action": "s3:GetObject*",
                "Resource": ["arn:aws:s3:::{}/*".format(bucket)],
            },
        ],
    }


def write_only(bucket):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": ["arn:aws:s3:::{}/*".format(bucket)],
            }
        ],
    }
