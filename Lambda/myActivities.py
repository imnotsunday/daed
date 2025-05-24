import json
import os
import base64
import hmac
import hashlib
import boto3

dynamodb = boto3.client('dynamodb')
TABLE = os.environ['TABLE_ACTIVITIES']
SECRET = os.environ['JWT_SECRET']

def decode_jwt(token, secret):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        msg = f"{parts[0]}.{parts[1]}".encode()
        sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        expected = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
        if expected != parts[2]:
            return None
        payload = base64.urlsafe_b64decode(parts[1] + '==')
        return json.loads(payload.decode())
    except:
        return None

def lambda_handler(event, context):
    headers = event.get('headers', {})
    token = headers.get('Authorization') or headers.get('authorization')

    if not token or not token.startswith('Bearer '):
        return { "statusCode": 401, "body": json.dumps({ "message": "Missing token" }) }

    user = decode_jwt(token.replace('Bearer ', ''), SECRET)
    if not user or user.get('role') != 'creator':
        return { "statusCode": 403, "body": json.dumps({ "message": "Access denied" }) }

    try:
        result = dynamodb.scan(
            TableName=TABLE,
            FilterExpression="createdBy = :uid",
            ExpressionAttributeValues={":uid": {"S": user["userId"]}}
        )

        items = [
            {k: list(v.values())[0] for k, v in item.items()}
            for item in result.get('Items', [])
        ]

        return {
            "statusCode": 200,
            "headers": { "Access-Control-Allow-Origin": "*" },
            "body": json.dumps(items)
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({ "message": "Error listing activities", "error": str(e) })
        }
