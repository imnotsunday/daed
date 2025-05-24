import json
import os
import base64
import hmac
import hashlib
from datetime import datetime
import boto3

# Init
dynamodb = boto3.client('dynamodb')
TABLE_QUIZ = os.environ.get('TABLE_QUIZ', 'QuizQuestions')
TABLE_SUBMISSIONS = os.environ.get('TABLE_SUBMISSIONS', 'Submissions')
TABLE_SKILLS = os.environ.get('TABLE_SKILLS', 'Skills')
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
        return json.loads(payload_json.decode())
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
        answers = body.get('answers')  # answers = {"q1": "A", "q2": "B"}

        if not activity_id or not answers:
            return {"statusCode": 400, "body": json.dumps({"message": "Missing activityId or answers"})}

        # 1. ดึงคำถามทั้งหมดจาก activity นี้
        result = dynamodb.query(
            TableName=TABLE_QUIZ,
            KeyConditionExpression="activityId = :aid",
            ExpressionAttributeValues={":aid": {"S": activity_id}}
        )

        correct = 0
        total = 0
        skill_results = []

        for item in result.get('Items', []):
            question = {k: list(v.values())[0] for k, v in item.items()}
            qid = question['questionId']
            total += 1
            is_correct = qid in answers and answers[qid] == question['correctAnswer']
            if is_correct:
                correct += 1
            skill_results.append({
                "name": question['relatedSkill'],
                "pass": is_correct
            })

        # 2. เก็บลง TABLE_SUBMISSIONS
        dynamodb.put_item(
            TableName=TABLE_SUBMISSIONS,
            Item={
                "activityId": {"S": activity_id},
                "userId": {"S": user['userId']},
                "score": {"N": str(correct)},
                "total": {"N": str(total)},
                "skills": {"S": json.dumps(skill_results)},
                "answers": {"S": json.dumps(answers)},
                "timestamp": {"S": datetime.utcnow().isoformat()}
            }
        )

        # 3. เพิ่ม skill ที่ผ่านเท่านั้นลง TABLE_SKILLS
        for s in skill_results:
            if s["pass"]:
                dynamodb.put_item(
                    TableName=TABLE_SKILLS,
                    Item={
                        "userId": {"S": user['userId']},
                        "skillName": {"S": s["name"]},
                        "acquiredFrom": {"S": activity_id},
                        "dateAcquired": {"S": datetime.utcnow().date().isoformat()}
                    }
                )

        return {
            "statusCode": 200,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({
                "message": "Quiz submitted successfully",
                "score": correct,
                "total": total,
                "skills": skill_results
            })
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "Quiz submission failed", "error": str(e)})
        }
