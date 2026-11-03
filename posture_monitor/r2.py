"""State object on R2 over the S3 API, signed with SigV4 using the standard library only (SPEC-001 R6).

    python -m posture_monitor.r2 get <key> <file>   # a missing object leaves <file> absent, exit 0
    python -m posture_monitor.r2 put <key> <file>
"""
import hashlib
import hmac
import os
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from urllib.parse import quote, urlsplit

BUCKET = 'posture-monitor'


def _hmac(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def signed_request(method, endpoint, bucket, key, access_key, secret_key, body=b'', now=None):
    now = now or datetime.now(UTC)
    amz_date, day = now.strftime('%Y%m%dT%H%M%SZ'), now.strftime('%Y%m%d')
    host = urlsplit(endpoint).netloc
    path = f'/{bucket}/{quote(key, safe="/")}'
    payload_hash = hashlib.sha256(body).hexdigest()
    headers = {'host': host, 'x-amz-content-sha256': payload_hash, 'x-amz-date': amz_date}
    signed = ';'.join(sorted(headers))
    canonical = '\n'.join([method, path, '', *(f'{k}:{headers[k]}' for k in sorted(headers)), '', signed,
                           payload_hash])
    scope = f'{day}/auto/s3/aws4_request'
    to_sign = '\n'.join(['AWS4-HMAC-SHA256', amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = _hmac(_hmac(_hmac(_hmac(f'AWS4{secret_key}'.encode(), day), 'auto'), 's3'), 'aws4_request')
    signature = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    headers['Authorization'] = (f'AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, '
                                f'Signature={signature}')
    del headers['host']
    return urllib.request.Request(endpoint + path, data=body if method == 'PUT' else None, method=method,
                                  headers=headers)


def main(argv=None, env=os.environ):
    op, key, path = argv or sys.argv[1:]
    creds = (env['POSTURE_R2_ENDPOINT'], BUCKET, key, env['POSTURE_R2_ACCESS_KEY_ID'],
             env['POSTURE_R2_SECRET_ACCESS_KEY'])
    try:
        if op == 'get':
            try:
                with urllib.request.urlopen(signed_request('GET', *creds), timeout=30) as resp:
                    data = resp.read()
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    return 0
                raise
            with open(path, 'wb') as f:
                f.write(data)
        elif op == 'put':
            with open(path, 'rb') as f:
                urllib.request.urlopen(signed_request('PUT', *creds, body=f.read()), timeout=30).close()
        else:
            raise SystemExit(f'unknown operation {op}')
    except (OSError, urllib.error.URLError) as exc:
        print(f'r2 {op} failed: {type(exc).__name__}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
