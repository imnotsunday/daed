import json
import os
import base64
import hmac
import hashlib
import time
import boto3
from datetime import datetime

# ENV
SECRET = os.environ.get('JWT_SECRET', 'default-secret')
TABLE = os.environ.get('TABLE_PROOFS', 'Proofs')
BUCKET = os.environ.get('S3_BUCKET_NAME', 'your-bucket-name')
EXPIRES_IN = int(os.environ.get('UPLOAD_EXPIRES_IN', '3600'))

s3 = boto3.client('s3')
dynamodb = boto3.client('dynamodb')

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
        return payload
    except:
        return None

def lambda_handler(event, context):
    headers = event.get('headers', {})
    token = headers.get('Authorization') or headers.get('authorization')
    if not token or not token.startswith('Bearer '):
        return {"statusCode": 401, "body": json.dumps({"message": "Missing or invalid token"})}
    
    token = token.replace('Bearer ', '')
    user = decode_jwt(token, SECRET)
    if not user or user.get('role') != 'student':
        return {"statusCode": 403, "body": json.dumps({"message": "Access denied"})}

    try:
        body = json.loads(event.get('body', '{}'))
        activity_id = body.get('activityId')
        file_name = body.get('fileName')

        if not activity_id or not file_name:
            return {"statusCode": 400, "body": json.dumps({"message": "Missing activityId or fileName"})}

        object_key = f"{user['userId']}/{activity_id}/{file_name}"

        # 1. Generate pre-signed URL
        url = s3.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': BUCKET,
                'Key': object_key,
                'ContentType': 'application/octet-stream'
            },
            ExpiresIn=EXPIRES_IN
        )

        # 2. Save URL reference in DynamoDB
        dynamodb.put_item(
            TableName=TABLE,
            Item={
                "activityId": {"S": activity_id},
                "userId": {"S": user['userId']},
                "proofUrl": {"S": f"https://{BUCKET}.s3.amazonaws.com/{object_key}"},
                "uploadedAt": {"S": datetime.utcnow().isoformat()}
            }
        )

        return {
            "statusCode": 200,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"uploadUrl": url})
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "Upload failed", "error": str(e)})
        }
