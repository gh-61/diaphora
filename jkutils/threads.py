#!/usr/bin/python3

"""
Threads support
Copyright (c) 2023, Joxean Koret

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

__all__ = ["threads_apply"]

import time
import threading

#-------------------------------------------------------------------------------
def threads_apply(threads, targets, wait_time, log_refresh, timeout, cancel_event=None):
  """
  Run a number of @threads calling a function with arguments from @targets,
  waiting and checking the threads if they finished every @wait_time seconds,
  calling @log_refresh whenever it's required.

  If @cancel_event is provided (a threading.Event), it will be set on
  cancellation so worker threads can check it and exit early.
  """
  times = 0
  first = True
  threads_list = []
  try:
    while first or len(targets) > 0 or len(threads_list) > 0:
      first = False
      times += 1

      # Fill all available thread slots at once
      while len(targets) > 0 and len(threads_list) < threads:
        item = targets.pop()
        target = item["target"]
        args = item["args"]

        t = threading.Thread(target=target, args=args)
        t.time = time.monotonic()
        t.timeout = False

        for key in item.keys():
          if key not in ["target", "args"]:
            setattr(t, key, item[key])

        t.start()
        threads_list.append(t)

      # Reap finished threads
      for i in range(len(threads_list) - 1, -1, -1):
        t = threads_list[i]
        if not t.is_alive():
          if log_refresh:
            log_refresh(f"[Parallel] Heuristic '{t.name}' done")
          del threads_list[i]

      # Check timeouts and wait
      for t in threads_list:
        if time.monotonic() - t.time > timeout:
          t.timeout = True

      if threads_list:
        threads_list[0].join(wait_time)

      if times % 50 == 0:
        names = []
        for x in threads_list:
          names.append(x.name)
        tmp_names = ", ".join(names)
        log_refresh(f"[Parallel] {len(threads_list)} thread(s) still running: {tmp_names}")
  except:
    # On cancellation or any error, signal worker threads to stop
    if cancel_event is not None:
      cancel_event.set()
    # Clear remaining targets so no new threads are spawned
    targets.clear()
    # Wait for running threads to finish (they should check cancel_event)
    for t in threads_list:
      t.join(timeout=5)
    raise
