import json
import os
import base64
import hmac
import hashlib
import uuid
import boto3

SECRET = os.environ.get('JWT_SECRET', 'default-secret')
TABLE_ACTIVITIES = os.environ.get('TABLE_ACTIVITIES', 'Activities')
TABLE_QUIZ = os.environ.get('TABLE_QUIZ', 'QuizQuestions')

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
    if not user or user.get('role') != 'creator':
        return {"statusCode": 403, "body": json.dumps({"message": "Only creators can create activities"})}

    try:
        body = json.loads(event.get('body', '{}'))
        name = body.get('name')
        description = body.get('description')
        event_date = body.get('eventDate')
        soft_skills = body.get('softSkills', [])
        hard_skills = body.get('hardSkills', [])
        quiz = body.get('quiz', [])  # optional list of questions

        if not name or not event_date:
            return {"statusCode": 400, "body": json.dumps({"message": "Missing name or eventDate"})}

        activity_id = str(uuid.uuid4())

        # ✅ แปลง soft/hard skills เป็น JSON string ก่อนเก็บ
        dynamodb.put_item(
            TableName=TABLE_ACTIVITIES,
            Item={
                "activityId": {"S": activity_id},
                "name": {"S": name},
                "description": {"S": description or ""},
                "eventDate": {"S": event_date},
                "status": {"S": "pending"},
                "createdBy": {"S": user["userId"]},
                "softSkills": {"S": json.dumps(soft_skills)},
                "hardSkills": {"S": json.dumps(hard_skills)}
            }
        )

        # 2. Save quiz questions if any
        for i, q in enumerate(quiz):
            dynamodb.put_item(
                TableName=TABLE_QUIZ,
                Item={
                    "activityId": {"S": activity_id},
                    "questionId": {"S": f"q{i+1}"},
                    "question": {"S": q["question"]},
                    "choices": {"SS": q["choices"]},
                    "correctAnswer": {"S": q["correctAnswer"]},
                    "relatedSkill": {"S": q["relatedSkill"]}
                }
            )

        return {
            "statusCode": 200,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"message": "Activity created", "activityId": activity_id})
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "Failed to create activity", "error": str(e)})
        }
