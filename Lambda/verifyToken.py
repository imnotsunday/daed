import json
import os
import base64
import hmac
import hashlib
import time

SECRET = os.environ.get('JWT_SECRET', 'default-secret')

def decode_jwt(token, secret):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None

        header_b64, payload_b64, signature_b64 = parts

        msg = f"{header_b64}.{payload_b64}".encode()
        signature_check = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        signature_check_b64 = base64.urlsafe_b64encode(signature_check).rstrip(b'=').decode()

        if signature_b64 != signature_check_b64:
            return None

        payload_json = base64.urlsafe_b64decode(payload_b64 + '==')
        payload = json.loads(payload_json.decode())

        if 'exp' in payload and time.time() > payload['exp']:
            return None

        return payload
    except Exception:
        return None

def lambda_handler(event, context):
    headers = event.get('headers', {})
    token = headers.get('Authorization') or headers.get('authorization')

    if not token or not token.startswith('Bearer '):
        return {
            "statusCode": 401,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"message": "Missing or invalid token"})
        }

    token = token.replace('Bearer ', '')
    user = decode_jwt(token, SECRET)

    if not user:
        return {
            "statusCode": 403,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"message": "Invalid or expired token"})
        }

    # ✅ ส่งข้อมูล user กลับให้ใช้งานต่อได้
    return {
        "statusCode": 200,
        "headers": {"Access-Control-Allow-Origin": "*"},
        "body": json.dumps({"user": user})
    }
