#!/usr/bin/python3

import os
import platform
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor, wait, as_completed
from multiprocessing.managers import BaseManager
from pathlib import Path
from queue import Queue
from random import randrange
from sqlite3 import Connection
from time import time
from typing import Optional, Tuple, cast

DIAPHORA = str(Path(__file__).resolve().parent / "diaphora.py")
DIAPHORA_DIR = str(Path(__file__).resolve().parent)


def _find_ida() -> str:
    """Find idat/idat64 binary from IDADIR env var, PATH, or common locations."""
    suffix = ".exe" if platform.system() == "Windows" else ""
    # IDA 9.x uses "idat", older versions use "idat64"
    candidates_names = ["idat" + suffix, "idat64" + suffix]

    # 1) IDADIR env var
    idadir = os.getenv("IDADIR")
    if idadir:
        for binary in candidates_names:
            candidate = os.path.join(idadir, binary)
            if os.path.isfile(candidate):
                return candidate

    # 2) Already on PATH
    for binary in candidates_names:
        found = shutil.which(binary)
        if found:
            return found

    # 3) Common install locations
    search_dirs = []
    if platform.system() == "Windows":
        prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        # Search for any IDA installation in Program Files
        if os.path.isdir(prog_files):
            for entry in os.listdir(prog_files):
                if "ida" in entry.lower():
                    search_dirs.append(os.path.join(prog_files, entry))
    else:
        search_dirs = [
            os.path.expanduser("~/idapro"),
            os.path.expanduser("~/ida"),
            "/opt/idapro",
            "/opt/ida",
        ]

    for search_dir in search_dirs:
        for binary in candidates_names:
            candidate = os.path.join(search_dir, binary)
            if os.path.isfile(candidate):
                return candidate

    # Fallback: hope it's on PATH at runtime
    return candidates_names[0]


IDA = _find_ida()

###############################################
# Database merge adapted from
# https://stackoverflow.com/a/68526717


def merge_databases(db1: str, db2: str, db_con: Optional[Connection]) -> Connection:
    print(f"Merging {db2} into {db1}")
    if db_con is None:
        db_con = sqlite3.connect(db1)

    db_con.execute("ATTACH ? as dba", (db2,))

    db_con.execute("BEGIN")
    for row in db_con.execute("SELECT * FROM dba.sqlite_master WHERE type='table'"):
        table = row[1]
        source_count = db_con.execute(f"SELECT COUNT(*) FROM dba.[{table}]").fetchone()[0]
        before_count = db_con.execute(f"SELECT COUNT(*) FROM [{table}]").fetchone()[0]
        combine = f"INSERT OR IGNORE INTO [{table}] SELECT * FROM dba.[{table}]"
        db_con.execute(combine)
        after_count = db_con.execute(f"SELECT COUNT(*) FROM [{table}]").fetchone()[0]
        inserted = after_count - before_count
        if inserted < source_count:
            dropped = source_count - inserted
            print(f"WARNING: merge of table '{table}': {dropped}/{source_count} rows dropped (duplicates)")
    db_con.commit()
    db_con.execute("detach database dba")

    return db_con


###############################################


def get_idb(target: Path) -> Path:
    target_idb = target.parent / (target.name + ".i64")
    if not target_idb.exists():
        env = os.environ.copy()
        env["TVHEADLESS"] = "1"
        log_path = str(target.parent / f"{target.stem}_analysis.log")
        subprocess.run(
            [IDA, f"-L{log_path}", "-B", str(target)],
            env=env,
        )
    return target_idb


def start_exporter(args: Tuple[Path, Path, int, int, int, bytes]) -> int:
    tmpdir, source_idb, worker_id, nbr_of_workers, port, authkey = args
    target = tmpdir / (source_idb.name[: -len(".i64")] + str(worker_id) + ".i64")
    shutil.copyfile(source_idb, target)

    authkey_b64 = b64encode(authkey).decode("ASCII")
    script_arg = f"{DIAPHORA} {worker_id} {nbr_of_workers} {port} {authkey_b64}"

    env = os.environ.copy()
    env["TVHEADLESS"] = "1"
    env["PYTHONPATH"] = env.get("PYTHONPATH", "") + os.pathsep + DIAPHORA_DIR

    worker_log = str(tmpdir / f"worker_{worker_id}.log")
    cmd = [IDA, "-a", "-A", f"-S{script_arg}", f"-L{worker_log}", str(target)]
    result = subprocess.run(cmd, env=env)

    # Print worker log if it exists (for debugging)
    if os.path.exists(worker_log):
        with open(worker_log, "r", errors="replace") as f:
            content = f.read().strip()
            if content:
                for line in content.split("\n")[-20:]:
                    print(f"  [worker {worker_id} log] {line}")

    try:
        target.unlink()
    except OSError:
        pass

    if result.returncode != 0:
        raise RuntimeError(
            f"Worker {worker_id} IDA process exited with code {result.returncode}. "
            f"See {worker_log} for details."
        )

    print(f"Worker {worker_id} done")
    return worker_id


# Module-level queues so they can be pickled on Windows (spawn mode)
_job_queue: Queue[Tuple[int, int]] = Queue()
_report_queue: Queue[int] = Queue()


def _get_job_queue():
    return _job_queue


def _get_report_queue():
    return _report_queue


class QueueManager(BaseManager):
    pass


QueueManager.register("get_job_queue", callable=_get_job_queue)
QueueManager.register("get_report_queue", callable=_get_report_queue)


def start_queues() -> Tuple[QueueManager, int, bytes]:
    m: Optional[QueueManager] = None
    port = randrange(49152, 65536)
    authkey = secrets.token_bytes()

    attempts = 0
    max_attempts = 100
    while m is None:
        try:
            m = QueueManager(address=("localhost", port), authkey=authkey)
            m.start()
        except OSError:
            m = None
            port = randrange(49152, 65536)
            attempts += 1
            if attempts >= max_attempts:
                raise RuntimeError(f"Failed to bind a port after {max_attempts} attempts")

    return m, port, authkey


def merge_while_exporting(
    qm: QueueManager, number_of_workers: int, number_of_jobs: int,
    tmpdir: Path, target: Path, timeout: float = 10800,
) -> Tuple[Path, int]:
    """Merge worker databases as soon as exports are done.

    Args:
        timeout: seconds to wait with no messages at all before considering workers dead.
                 Resets whenever any message (job report or completion) is received.
    """
    assert number_of_workers > 0
    db_files = [
        str(tmpdir / f"{target.name}{i}.sqlite") for i in range(number_of_workers)
    ]
    remaining_workers = {i for i in range(number_of_workers)}
    main_worker: Optional[int] = None
    db_con: Optional[Connection] = None
    jobs_done = 0

    completed_workers = set()
    while remaining_workers:
        try:
            worker_id, report = cast(Tuple[int, int], qm.get_report_queue().get(timeout=timeout))
        except Exception:
            missing = remaining_workers - completed_workers
            raise RuntimeError(
                f"Timed out waiting for workers {missing} after {timeout}s of silence. "
                f"{len(completed_workers)}/{number_of_workers} workers completed, "
                f"{jobs_done}/{number_of_jobs} jobs done. "
                f"Results are incomplete; aborting merge."
            )

        if report >= 0:
            jobs_done += 1
            print(f"Job {report} done by worker {worker_id} ({jobs_done}/{number_of_jobs})")
            continue

        completed_workers.add(worker_id)
        if main_worker is None:
            main_worker = worker_id
        else:
            db_con = merge_databases(db_files[main_worker], db_files[worker_id], db_con)
        remaining_workers.discard(worker_id)

    if main_worker is None:
        raise RuntimeError("No workers completed successfully")

    if db_con is not None:
        db_con.close()

    return Path(db_files[main_worker]), main_worker


if __name__ == "__main__":
    start = time()

    # Extract --timeout before processing positional args
    argv = sys.argv[1:]
    merge_timeout = 10800  # 3 hours default
    if "--timeout" in argv:
        idx = argv.index("--timeout")
        if idx + 1 < len(argv):
            merge_timeout = int(argv[idx + 1])
            argv = argv[:idx] + argv[idx + 2:]
        else:
            argv = argv[:idx]

    if len(argv) < 1:
        print(f"Usage: {sys.argv[0]} <file> [<nbr workers>] [<nbr jobs>] [--timeout <seconds>]")
        sys.exit(1)
    target = Path(argv[0]).resolve()

    if target.exists():
        target_idb = get_idb(target)
    else:
        # Exe not found, try to find an existing .i64 or .idb
        target_idb = target.parent / (target.name + ".i64")
        if not target_idb.exists():
            target_idb = target.parent / (target.name + ".idb")
        if not target_idb.exists():
            print(f"Error: neither {target} nor {target.name}.i64/.idb found")
            sys.exit(1)
        print(f"Binary not found, using existing IDB: {target_idb}")

    if not target_idb.exists():
        print(f"Error: IDA analysis failed, no idb at {target_idb}")
        sys.exit(1)
    print(f"idb retrieved in {time() - start:.3f} seconds")

    number_of_workers = max((os.cpu_count() or 4) - 1, 1)
    if len(argv) > 1:
        number_of_workers = int(argv[1])
    number_of_jobs = 2 * number_of_workers
    if len(argv) > 2:
        number_of_jobs = int(argv[2])

    if number_of_jobs < number_of_workers or number_of_workers < 1:
        print(f"Error: need number_of_jobs ({number_of_jobs}) >= number_of_workers ({number_of_workers}) > 0")
        sys.exit(1)

    queue_manager, port, authkey = start_queues()

    print(f"Starting {number_of_jobs} jobs on {number_of_workers} workers (timeout: {merge_timeout}s)")
    print(f"Using IDA: {IDA}")

    exit_code = 0
    with tempfile.TemporaryDirectory(dir=target.parent) as tmpdirname:
        tmpdir = Path(tmpdirname)
        print(f"Working in {tmpdir}")

        try:
            with ThreadPoolExecutor(max_workers=number_of_workers) as pool:
                futures = [
                    pool.submit(
                        start_exporter,
                        (tmpdir, target_idb, i, number_of_workers, port, authkey),
                    )
                    for i in range(number_of_workers)
                ]

                # send jobs
                for i in range(number_of_jobs):
                    print(f"Sending job {i} of {number_of_jobs}")
                    queue_manager.get_job_queue().put((i, number_of_jobs))

                # send kill switches
                for i in range(number_of_workers):
                    print(f"Sending killswitch {i}")
                    queue_manager.get_job_queue().put((-1, number_of_jobs))

                # Start merging results asap
                merged_database, last_worker = merge_while_exporting(
                    queue_manager, number_of_workers, number_of_jobs,
                    tmpdir, target, timeout=merge_timeout,
                )
                print(f"Functions exported in {time() - start:.3f} seconds")

                # Wait for all workers to actually exit
                failed_workers = []
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        failed_workers.append(e)
                        print(f"ERROR: Worker raised exception: {e}")

                if failed_workers:
                    raise RuntimeError(
                        f"{len(failed_workers)}/{number_of_workers} workers failed. Aborting export."
                    )

            # Run diaphora one more time to get global info
            print("Finalizing database...")
            (merged_database.parent / (merged_database.name + "-crash")).touch()
            start_exporter((tmpdir, target_idb, last_worker, last_worker, port, authkey))
            print(f"Database exported in {time() - start:.3f} seconds")

            output_path = target.parent / f"{target.name}.sqlite"
            shutil.move(str(merged_database), str(output_path))

            # Validate and clean up output database
            val_con = sqlite3.connect(str(output_path))
            try:
                tables = [t[0] for t in val_con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()]
                if "functions" not in tables:
                    raise RuntimeError("Output database is missing 'functions' table")
                func_count = val_con.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
                print(f"Validation: {func_count} functions across {len(tables)} tables")
                if func_count == 0:
                    raise RuntimeError("Output database contains 0 functions - export failed")

                # Deduplicate version table (each worker inserts a row)
                if "version" in tables:
                    ver_count = val_con.execute("SELECT COUNT(*) FROM version").fetchone()[0]
                    if ver_count > 1:
                        val_con.execute("DELETE FROM version WHERE rowid NOT IN (SELECT MIN(rowid) FROM version)")
                        val_con.commit()
                        print(f"Deduplicated version table: {ver_count} -> 1 row")
            finally:
                val_con.close()

            print(f"Output: {output_path}")

        except Exception as e:
            print(f"Error during parallel export: {e}")
            import traceback
            traceback.print_exc()
            exit_code = 1

    queue_manager.shutdown()
    sys.exit(exit_code)
