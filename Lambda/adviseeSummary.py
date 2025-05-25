import json
import os
import boto3
import base64
import hmac
import hashlib
from boto3.dynamodb.conditions import Attr

# 🔧 Environment variables
dynamodb = boto3.resource('dynamodb')
SECRET = os.environ.get('JWT_SECRET', 'default-secret')
TABLE_USERS = os.environ.get('TABLE_USERS', 'Users')
users_table = dynamodb.Table(TABLE_USERS)

# ✅ ฟังก์ชันนี้ต้องอยู่ตรงนี้ (ก่อน lambda_handler)
def decode_jwt(token, secret):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header_b64, payload_b64, signature_b64 = parts
        msg = f"{header_b64}.{payload_b64}".encode()
        sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
        if sig_b64 != signature_b64:
            return None
        payload_json = base64.urlsafe_b64decode(payload_b64 + '==')
        return json.loads(payload_json.decode())
    except:
        return None

# ✅ main Lambda handler
def lambda_handler(event, context):
    token = event.get('headers', {}).get('Authorization') or event.get('headers', {}).get('authorization')
    if not token or not token.startswith('Bearer '):
        return {"statusCode": 401, "body": json.dumps({"message": "Missing or invalid token"})}

    user = decode_jwt(token.replace('Bearer ', ''), SECRET)
    if not user or user.get('role') != 'advisor':
        return {"statusCode": 403, "body": json.dumps({"message": "Access denied"})}

    try:
        response = users_table.scan(
            FilterExpression=Attr('role').eq('student')
        )
        students = []
        for item in response.get('Items', []):
            students.append({
                "studentId": item.get("userId"),
                "name": item.get("name"),
                "totalActivities": 0
            })

        return {
            "statusCode": 200,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps(students)
        }
    except Exception as e:
        print("ERROR in /advisee-summary:", str(e))
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "Failed to load advisee summary", "error": str(e)})
        }