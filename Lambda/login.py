import json
import os
import base64
import hmac
import hashlib
import time
import urllib.request
import boto3  # ✅ เพิ่ม boto3

# Environment variables
TU_AUTH_API = 'https://restapi.tu.ac.th/api/v1/auth/Ad/verify2'
APPLICATION_KEY = os.environ.get('TU_APP_KEY', '')
SECRET = os.environ.get('JWT_SECRET', 'default-secret')
TABLE_USERS = os.environ.get('TABLE_USERS', 'Users')  # ✅ เพิ่มชื่อ table

# DynamoDB
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table(TABLE_USERS)

def build_jwt(payload, secret):
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
    msg = header_b64 + b"." + payload_b64
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=')
    return f"{header_b64.decode()}.{payload_b64.decode()}.{sig_b64.decode()}"

def lambda_handler(event, context):
    try:
        body = json.loads(event.get('body', '{}'))
        username = body.get('username')
        password = body.get('password')

        if not username or not password:
            return {"statusCode": 400, "body": json.dumps({"message": "Missing credentials"})}

        allowed_roles = ['admin', 'creator', 'advisor']
        if username == password and username in allowed_roles:
            payload = {
                "userId": username,
                "name": username.title(),
                "role": username,
                "exp": int(time.time()) + 3600
            }
            token = build_jwt(payload, SECRET)
            return {
                "statusCode": 200,
                "headers": {"Access-Control-Allow-Origin": "*"},
                "body": json.dumps({"token": token, "user": payload})
            }

        # ✅ ตรวจสอบกับ TU Auth API
        req = urllib.request.Request(
            TU_AUTH_API,
            data=json.dumps({"UserName": username, "PassWord": password}).encode(),
            headers={
                'Content-Type': 'application/json',
                'Application-Key': APPLICATION_KEY
            }
        )
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())

        if 'displayname_en' not in data:
            return {"statusCode": 401, "body": json.dumps({"message": "Invalid TU credentials"})}

        payload = {
            "userId": username,
            "name": data['displayname_en'],
            "role": "student",
            "exp": int(time.time()) + 3600
        }

        # ✅ เพิ่มผู้ใช้เข้า DynamoDB ถ้ายังไม่มี
        existing = users_table.get_item(Key={'userId': username})
        if 'Item' not in existing:
            users_table.put_item(Item={
                'userId': username,
                'name': data['displayname_en'],
                'role': 'student'
            })

        token = build_jwt(payload, SECRET)
        return {
            "statusCode": 200,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"token": token, "user": payload})
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "Login failed", "error": str(e)})
        }
