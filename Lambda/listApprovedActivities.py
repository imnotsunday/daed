import json
import os
import base64
import hmac
import hashlib
import boto3
import time

dynamodb = boto3.client('dynamodb')
TABLE = os.environ.get('TABLE_ACTIVITIES', 'Activities')
SECRET = os.environ.get('JWT_SECRET', 'default-secret')
STATUS_INDEX = 'status-index'

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
        payload = json.loads(payload_json.decode())
        if 'exp' in payload and payload['exp'] < time.time():
            return None

        return payload
    except:
        return None

def lambda_handler(event, context):
    headers = event.get('headers', {})
    token = headers.get('Authorization') or headers.get('authorization')

    print("HEADERS:", headers)
    print("TOKEN RAW:", token)
    
    if not token or not token.startswith('Bearer '):
        return {
            "statusCode": 401,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"message": "Missing or invalid token"})
        }

    token = token.replace('Bearer ', '')
    user = decode_jwt(token, SECRET)
    if not user or user.get('role') != 'student':
        return {
            "statusCode": 403,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"message": "Access denied"})
        }

    try:
        result = dynamodb.query(
            TableName=TABLE,
            IndexName=STATUS_INDEX,
            KeyConditionExpression="#s = :approved",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":approved": {"S": "approved"}}
        )

        items = [ {k: list(v.values())[0] for k,v in item.items()} for item in result.get('Items', []) ]

        return {
            "statusCode": 200,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps(items)
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "Error listing activities", "error": str(e)})
        }
