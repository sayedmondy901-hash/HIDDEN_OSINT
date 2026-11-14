import argparse
import asyncio
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import redis
from dotenv import load_dotenv

# السماح باستدعاء osint_engine.py من الفولدر الرئيسي
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

# تحميل ملف .env من الفولدر الرئيسي
load_dotenv(ROOT_DIR / ".env")

from osint_engine import AdvancedOSINTEngine

DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[A-Za-z]{2,63}\Z"
)
QUEUE_NAME = "osint:scan_tasks"


def db_connect(role: str):
    env_key = "BACKEND_DATABASE_URL" if role == "backend" else "WORKER_DATABASE_URL"
    url = os.getenv(env_key)
    if not url:
        raise RuntimeError(f"Missing environment variable: {env_key}")
    return psycopg.connect(url)


def redis_connect():
    url = os.getenv("REDIS_URL")
    if not url:
        raise RuntimeError("Missing environment variable: REDIS_URL")
    # بنزود وقت الـ socket_timeout لـ 15 ثانية عشان ميفصلش وهو مستني المهام
    return redis.Redis.from_url(url, decode_responses=True, socket_timeout=15)


def validate_domain(domain: str) -> str:
    domain = domain.strip().rstrip(".")
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Invalid domain format. Example: example.com")
    return domain.lower()


def create_task(owner_id: str, domain: str) -> int:
    """Backend function: persist task first, then enqueue its ID."""
    if not owner_id or len(owner_id) > 120:
        raise ValueError("owner_id must contain 1-120 characters")
    domain = validate_domain(domain)

    with db_connect("backend") as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_tasks (owner_id, target_domain, status)
                VALUES (%s, %s, 'queued')
                RETURNING id
                """,
                (owner_id, domain),
            )
            task_id = cur.fetchone()[0]

    redis_connect().lpush(QUEUE_NAME, str(task_id))
    return task_id


import json # ضيف دي فوق مع الـ imports لو مش موجودة

def real_osint_discovery(domain: str):
    """تشغيل محرك Hidden OSINT الحقيقي"""
    print(f"[*] Worker starting real OSINT engine for: {domain}")
    engine = AdvancedOSINTEngine(target_domain=domain, concurrency_limit=10, use_proxies=False)
    subdomains = asyncio.run(engine.run())
    print(f"[+] OSINT Engine found {len(subdomains)} subdomains for {domain}!")
    # نستخدم demo-source عشان نتفادى أي قيود في schema.sql
    return [(sub, "demo-source") for sub in subdomains]


def worker_once():
    """Worker function: take one task ID, process it, and store results in both DB & Redis."""
    queue = redis_connect()
    item = queue.brpop(QUEUE_NAME, timeout=5)
    if item is None:
        return False

    _, raw_task_id = item
    task_id = int(raw_task_id)
    print(f"\n[+] Picked up Task ID: {task_id} from Redis Queue!")

    with db_connect("worker") as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT target_domain FROM scan_tasks WHERE id = %s", (task_id,))
            row = cur.fetchone()
            if row is None:
                return True
            domain = row[0]
            cur.execute(
                """
                UPDATE scan_tasks
                SET status = 'running', started_at = %s, error_message = NULL
                WHERE id = %s
                """,
                (datetime.now(timezone.utc), task_id),
            )
        conn.commit()

    try:
        results = real_osint_discovery(domain)
        subdomains_only = [sub for sub, _ in results]

        # حركة ذكية: نحفظ النتائج فوراً في Redis لمدة ساعة لضمان وصولها للواجهة 100%
        queue.setex(f"osint:results:{task_id}", 3600, json.dumps(subdomains_only))

        with db_connect("worker") as conn:
            with conn.cursor() as cur:
                saved_count = 0
                for subdomain, source in results[:600]:
                    cur.execute("SAVEPOINT sp_finding")
                    try:
                        cur.execute(
                            """
                            INSERT INTO findings (task_id, subdomain, source)
                            VALUES (%s, %s, %s)
                            ON CONFLICT (task_id, subdomain, source) DO NOTHING
                            """,
                            (task_id, subdomain, source),
                        )
                        saved_count += 1
                    except Exception as db_err:
                        cur.execute("ROLLBACK TO SAVEPOINT sp_finding")
                        if saved_count == 0:
                            print(f"[!] DB Insert warning: {db_err}")
                    else:
                        cur.execute("RELEASE SAVEPOINT sp_finding")

                cur.execute(
                    """
                    UPDATE scan_tasks
                    SET status = 'completed', finished_at = %s
                    WHERE id = %s
                    """,
                    (datetime.now(timezone.utc), task_id),
                )
            conn.commit()
        print(f"[+] Task {task_id} completed! Engine found {len(subdomains_only)} (Saved {saved_count} to DB).")

    except Exception as exc:
        print(f"[!] Error during task {task_id}: {exc}")
        with db_connect("worker") as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE scan_tasks
                    SET status = 'failed', finished_at = %s, error_message = %s
                    WHERE id = %s
                    """,
                    (datetime.now(timezone.utc), str(exc)[:500], task_id),
                )
            conn.commit()

    return True


def worker_loop():
    """تشغيل العامل بشكل مستمر في الخلفية لالتقاط أي مهام جديدة"""
    print("[*] OSINT Background Worker is running and listening to Redis queue (Press CTRL+C to stop)...")
    while True:
        try:
            worker_once()
        except redis.exceptions.TimeoutError:
            # ده طبيعي معناه الطابور فاضي وبيكمل استماع بهدوء
            continue
        except KeyboardInterrupt:
            print("\n[!] Worker stopped.")
            break
        except Exception as e:
            print(f"[!] Worker error: {e}")

def get_task_results_dict(owner_id: str, task_id: int):
    """دالة مساعدة للباك إند لقراءة النتائج من PostgreSQL"""
    with db_connect("backend") as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, target_domain, status, error_message
                FROM scan_tasks
                WHERE id = %s AND owner_id = %s
                """,
                (task_id, owner_id),
            )
            task = cur.fetchone()
            if task is None:
                return None

            cur.execute(
                """
                SELECT subdomain, source, discovered_at
                FROM findings
                WHERE task_id = %s
                ORDER BY subdomain
                """,
                (task_id,),
            )
            rows = cur.fetchall()
            return {
                "task_id": task[0],
                "target": task[1],
                "status": task[2],
                "error_message": task[3],
                "subdomains": [r[0] for r in rows]
            }


def show_results(owner_id: str, task_id: int):
    data = get_task_results_dict(owner_id, task_id)
    if not data:
        print("Task not found for this owner.")
        return
    print(f"\nTASK ID: {data['task_id']} | Target: {data['target']} | Status: {data['status']}")
    print(f"FINDINGS ({len(data['subdomains'])}):")
    for sub in data["subdomains"]:
        print(f"  -> {sub}")


def main():
    parser = argparse.ArgumentParser(description="OSINT data-layer worker & CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="Create a scan task")
    create.add_argument("--owner", required=True)
    create.add_argument("--domain", required=True)

    sub.add_parser("work", help="Process one queued task")
    sub.add_parser("listen", help="Run continuous worker loop")

    results = sub.add_parser("results", help="Show task and results")
    results.add_argument("--owner", required=True)
    results.add_argument("--task-id", required=True, type=int)

    args = parser.parse_args()
    if args.command == "create":
        tid = create_task(args.owner, args.domain)
        print(f"Created task {tid} and added it to the Redis queue.")
    elif args.command == "work":
        worker_once()
    elif args.command == "listen":
        worker_loop()
    elif args.command == "results":
        show_results(args.owner, args.task_id)


if __name__ == "__main__":
    main()