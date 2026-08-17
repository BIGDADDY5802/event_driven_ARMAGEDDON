import json
import os
import uuid
import datetime
import boto3
import pymysql

secrets = boto3.client("secretsmanager")

# GAP-3 (tracked): the secret is fetched fresh on every invocation. This is
# the safest default (rotation takes effect instantly, nothing sensitive
# sits in a warm container longer than necessary) but adds a Secrets
# Manager call to every request. Under real load this should move to a
# module-level cache with a TTL. See README "Known gaps".


def get_secret(secret_arn: str) -> dict:
    resp = secrets.get_secret_value(SecretId=secret_arn)
    return json.loads(resp["SecretString"])


def resp(status_code: int, body: dict):
    return {
        "statusCode": status_code,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body),
    }


def lambda_handler(event, context):
    # ---- Parse request body ----
    raw_body = event.get("body") or "{}"
    try:
        body = json.loads(raw_body)
    except Exception:
        return resp(400, {"ok": False, "error": "Invalid JSON body"})

    # Length caps match the VARCHAR sizes in sql/schema.sql — belt and
    # suspenders alongside the parameterized query below.
    actor = str(body.get("actor", "unknown"))[:100]
    action = str(body.get("action", "unknown"))[:50]
    resource = str(body.get("resource", "unknown"))[:200]
    note = str(body.get("note", ""))[:500]

    # ---- Metadata ----
    event_id = str(uuid.uuid4())
    ts_utc = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    request_id = getattr(context, "aws_request_id", "no-request-id")

    source_ip = (
        (event.get("requestContext") or {})
        .get("http", {})
        .get("sourceIp", "unknown")
    )[:60]

    # ---- Resolve DB creds from Secrets Manager ----
    secret_arn = os.environ["DB_SECRET_ARN"]
    db = get_secret(secret_arn)

    host = db["host"]
    port = int(db.get("port", 3306))
    user = db["username"]
    password = db["password"]

    dbname = os.environ.get("DB_NAME") or db.get("dbname")
    if not dbname:
        return resp(500, {"ok": False, "error": "DB_NAME not set and dbname missing in secret"})

    timeout = int(os.environ.get("DB_CONNECT_TIMEOUT", "5"))

    # ---- Insert into DB ----
    conn = None
    try:
        conn = pymysql.connect(
            host=host,
            user=user,
            password=password,
            database=dbname,
            port=port,
            connect_timeout=timeout,
            read_timeout=timeout,
            write_timeout=timeout,
            autocommit=True,
            cursorclass=pymysql.cursors.DictCursor,
        )

        # Parameterized query — never string-interpolated SQL.
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO audit_events
                  (id, ts_utc, actor, action, resource, note, source_ip, request_id)
                VALUES
                  (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (event_id, ts_utc, actor, action, resource, note, source_ip, request_id),
            )

        return resp(200, {
            "ok": True,
            "event_id": event_id,
            "ts_utc": ts_utc,
            "request_id": request_id,
        })

    except pymysql.MySQLError:
        # Never leak the underlying exception (schema, engine, connection
        # details) to the caller. Real detail lives in CloudWatch Logs,
        # correlated by request_id.
        return resp(502, {
            "ok": False,
            "error": "DB_WRITE_FAILED",
            "request_id": request_id,
        })

    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
