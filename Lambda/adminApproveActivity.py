import json
import os
import base64
import hmac
import hashlib
import boto3

dynamodb = boto3.client('dynamodb')
TABLE = os.environ.get('TABLE_ACTIVITIES', 'Activities')
SECRET = os.environ.get('JWT_SECRET', 'default-secret')

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
    if not user or user.get('role') != 'admin':
        return {"statusCode": 403, "body": json.dumps({"message": "Only admin can approve activities"})}

    try:
        body = json.loads(event.get('body', '{}'))
        activity_id = body.get('activityId')

        if not activity_id:
            return {"statusCode": 400, "body": json.dumps({"message": "Missing activityId"})}

        # ✅ Update status = "approved"
        dynamodb.update_item(
            TableName=TABLE,
            Key={"activityId": {"S": activity_id}},
            UpdateExpression="SET #s = :approved",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":approved": {"S": "approved"}}
        )

        return {
            "statusCode": 200,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"message": f"Activity {activity_id} approved"})
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "Failed to approve activity", "error": str(e)})
        }
