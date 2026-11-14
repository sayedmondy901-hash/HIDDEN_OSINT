"""
Small educational prototype for the OSINT Data Layer & Message Queue.

It deliberately does NOT run real internet reconnaissance. The worker uses
a fixed demonstration result so the database, queue, and permissions can be
tested safely. Replace demo_discovery() only with an authorized OSINT worker.
"""
import argparse
import os
import re
import sys
from datetime import datetime, timezone

import psycopg
import redis


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
    return redis.Redis.from_url(url, decode_responses=True)


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

    # Simple demo queue. Production systems should use a durable queue pattern
    # (e.g. Redis Streams consumer groups/RabbitMQ acknowledgements) to handle
    # worker crashes between dequeue and completion.
    redis_connect().lpush(QUEUE_NAME, str(task_id))
    return task_id


def demo_discovery(domain: str):
    """Safe placeholder: no network calls; replace only for authorized targets."""
    return [
        (f"www.{domain}", "demo-source"),
        (f"mail.{domain}", "demo-source"),
    ]


def worker_once():
    """Worker function: take one task ID, process it, and store results."""
    queue = redis_connect()
    item = queue.brpop(QUEUE_NAME, timeout=5)
    if item is None:
        print("No task available.")
        return False

    _, raw_task_id = item
    task_id = int(raw_task_id)

    with db_connect("worker") as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT target_domain FROM scan_tasks WHERE id = %s",
                (task_id,),
            )
            row = cur.fetchone()
            if row is None:
                print(f"Task {task_id} does not exist; skipped.")
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

            try:
                results = demo_discovery(domain)
                for subdomain, source in results:
                    cur.execute(
                        """
                        INSERT INTO findings (task_id, subdomain, source)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (task_id, subdomain, source) DO NOTHING
                        """,
                        (task_id, subdomain, source),
                    )
                cur.execute(
                    """
                    UPDATE scan_tasks
                    SET status = 'completed', finished_at = %s
                    WHERE id = %s
                    """,
                    (datetime.now(timezone.utc), task_id),
                )
            except Exception as exc:
                cur.execute(
                    """
                    UPDATE scan_tasks
                    SET status = 'failed', finished_at = %s, error_message = %s
                    WHERE id = %s
                    """,
                    (datetime.now(timezone.utc), str(exc)[:500], task_id),
                )
                raise

    print(f"Task {task_id} completed.")
    return True


def show_results(owner_id: str, task_id: int):
    """Backend function: only return a task owned by this user."""
    with db_connect("backend") as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, target_domain, status, created_at, started_at, finished_at
                FROM scan_tasks
                WHERE id = %s AND owner_id = %s
                """,
                (task_id, owner_id),
            )
            task = cur.fetchone()
            if task is None:
                print("Task not found for this owner.")
                return

            print("\nTASK")
            print("ID | Target | Status | Created | Started | Finished")
            print(" | ".join(str(value) for value in task))

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
            print("\nFINDINGS")
            if not rows:
                print("No findings saved yet.")
            for row in rows:
                print(" | ".join(str(value) for value in row))


def main():
    parser = argparse.ArgumentParser(description="OSINT data-layer demo")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="Create a demo task")
    create.add_argument("--owner", required=True, help="Demo user ID, e.g. student1")
    create.add_argument("--domain", required=True, help="Authorized domain, e.g. example.com")

    sub.add_parser("work", help="Process one queued demo task")

    results = sub.add_parser("results", help="Show task and results")
    results.add_argument("--owner", required=True)
    results.add_argument("--task-id", required=True, type=int)

    args = parser.parse_args()
    try:
        if args.command == "create":
            task_id = create_task(args.owner, args.domain)
            print(f"Created task {task_id} and added it to the Redis queue.")
        elif args.command == "work":
            worker_once()
        elif args.command == "results":
            show_results(args.owner, args.task_id)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
