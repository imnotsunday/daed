import json
import os
import boto3
import base64
import hashlib
import hmac

s3 = boto3.client('s3')
BUCKET = os.environ['ACTIVITY_IMAGE_BUCKET']
JWT_SECRET = os.environ['JWT_SECRET']

def decode_jwt(token, secret):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        msg = f"{parts[0]}.{parts[1]}".encode()
        sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        expected_sig = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
        if expected_sig != parts[2]:
            return None
        payload = base64.urlsafe_b64decode(parts[1] + '==')
        return json.loads(payload.decode())
    except:
        return None

def lambda_handler(event, context):
    headers = event.get('headers', {})
    token = headers.get('Authorization') or headers.get('authorization')
    if not token or not token.startswith('Bearer '):
        return { 'statusCode': 401, 'body': json.dumps({ 'message': 'Missing token' }) }

    user = decode_jwt(token.replace('Bearer ', ''), JWT_SECRET)
    if not user or user.get('role') != 'creator':
        return { 'statusCode': 403, 'body': json.dumps({ 'message': 'Access denied' }) }

    body = json.loads(event['body'])
    file_name = body.get('fileName')
    content_type = body.get('contentType')
    if not file_name or not content_type:
        return { 'statusCode': 400, 'body': json.dumps({ 'message': 'Missing fileName or contentType' }) }

    upload_key = f"activities/{file_name}"
    upload_url = s3.generate_presigned_url(
        ClientMethod='put_object',
        Params={
            'Bucket': BUCKET,
            'Key': upload_key,
            'ContentType': content_type
        },
        ExpiresIn=300
    )

    return {
        'statusCode': 200,
        'headers': { 'Access-Control-Allow-Origin': '*' },
        'body': json.dumps({
            'uploadUrl': upload_url,
            'fileUrl': f"https://{BUCKET}.s3.amazonaws.com/{upload_key}"
        })
    }
