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
TABLE_ACTIVITIES = os.environ.get('TABLE_ACTIVITIES', 'Activities')
TABLE_SUBMISSIONS = os.environ.get('TABLE_SUBMISSIONS', 'Submissions')
TABLE_SKILLS = os.environ.get('TABLE_SKILLS', 'Skills')
SECRET = os.environ.get('JWT_SECRET', 'super-secret-key')

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

def flatten(item):
    return {
        k: v.get('S') or v.get('N') or v.get('BOOL') or None
        for k, v in item.items()
    }

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
        answers = body.get('answers')

        if not activity_id or not answers:
            return {"statusCode": 400, "body": json.dumps({"message": "Missing activityId or answers"})}

        # 1. ดึง soft skills จาก Activities
        activity_data = dynamodb.get_item(
            TableName=TABLE_ACTIVITIES,
            Key={"activityId": {"S": activity_id}}
        )
        soft_skills = []
        if 'Item' in activity_data:
            raw_soft = activity_data['Item'].get('softSkills', {}).get('S', '[]')
            try:
                parsed = json.loads(raw_soft)
                if isinstance(parsed, dict):
                    soft_skills = list(parsed.keys())
                elif isinstance(parsed, list):
                    soft_skills = parsed
            except:
                soft_skills = []

        # 2. ดึงคำถามทั้งหมดของ activity
        result = dynamodb.query(
            TableName=TABLE_QUIZ,
            KeyConditionExpression="activityId = :aid",
            ExpressionAttributeValues={":aid": {"S": activity_id}}
        )

        correct = 0
        total = 0
        skill_results = []

        for item in result.get('Items', []):
            question = flatten(item)
            qid = question.get('questionId')
            related_skill = (question.get('relatedSkill') or '').strip()
            correct_answer = question.get('correctAnswer')

            is_correct = qid in answers and answers[qid] == correct_answer
            total += 1
            if is_correct:
                correct += 1

            skill_results.append({
                "name": related_skill,
                "pass": is_correct
            })

        # 3. เพิ่ม soft skill ทั้งหมดให้ pass
        for soft in soft_skills:
            skill_results.append({
                "name": soft,
                "pass": True
            })

        # 4. เก็บลง TABLE_SUBMISSIONS
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

        # 5. เพิ่มเฉพาะ skill ที่ pass ลง TABLE_SKILLS
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
