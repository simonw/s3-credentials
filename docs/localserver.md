# Local credential server

The `s3-credentials localserver` command starts a local HTTP server that serves temporary S3 credentials. This is useful when you need to provide credentials to applications that can fetch them from an HTTP endpoint.

## Basic usage

To start a server that serves credentials for a bucket:

```bash
s3-credentials localserver my-bucket --duration 1h
```

This starts a server on `localhost:8094` that responds to `GET /` requests with JSON containing temporary AWS credentials.

The server will output:

```
Generating initial credentials...
Serving read-write credentials for bucket 'my-bucket' at http://localhost:8094/
Duration: 3600 seconds
Press Ctrl+C to stop
```

## Fetching credentials

Once the server is running, fetch credentials with:

```bash
curl http://localhost:8094/
```

This returns JSON like:

```json
{
  "AccessKeyId": "ASIAWXFXAIOZPAHAYHUG",
  "SecretAccessKey": "Nrnoc...",
  "SessionToken": "FwoGZXIvYXd...mr9Fjs=",
  "Expiration": "2025-12-16T12:00:00+00:00"
}
```

## Options

### Duration (required)

The `--duration` or `-d` option specifies how long credentials should be valid for. This must be between 15 minutes and 12 hours:

```bash
# 15 minutes
s3-credentials localserver my-bucket --duration 15m

# 1 hour
s3-credentials localserver my-bucket --duration 1h

# 12 hours
s3-credentials localserver my-bucket --duration 12h
```

### Port

Change the port with `-p` or `--port`:

```bash
s3-credentials localserver my-bucket --duration 1h --port 9000
```

### Host

Change the host to bind to with `--host`:

```bash
s3-credentials localserver my-bucket --duration 1h --host 0.0.0.0
```

### Read-only or write-only access

By default, credentials have read-write access. Use `--read-only` or `--write-only` for more restricted access:

```bash
# Read-only access
s3-credentials localserver my-bucket --duration 1h --read-only

# Write-only access
s3-credentials localserver my-bucket --duration 1h --write-only
```

### Prefix restriction

Restrict access to keys with a specific prefix:

```bash
s3-credentials localserver my-bucket --duration 1h --prefix "uploads/"
```

### Custom policy statements

Add custom IAM policy statements with `--statement`:

```bash
s3-credentials localserver my-bucket --duration 1h \
  --statement '{"Effect": "Allow", "Action": "textract:*", "Resource": "*"}'
```

## Credential caching

The server caches credentials internally and serves the same credentials until they expire. When the duration elapses, the server automatically generates new credentials.

This avoids issues with multiple simultaneous requests all triggering credential generation (dogpile effect), and ensures that applications fetching credentials within a short time window all receive the same credentials.

## Example: Using with AWS CLI profiles

You can configure an AWS CLI profile to fetch credentials from the local server. Add to your `~/.aws/config`:

```ini
[profile localserver]
credential_process = curl -s http://localhost:8094/
```

Then use:

```bash
aws s3 ls s3://my-bucket/ --profile localserver
```
