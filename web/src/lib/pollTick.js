/**
 * Marks the requests a background poll tick starts, so the API client can
 * treat them differently from a load the user asked for (api/client.js does
 * not retry a poll's GET after it times out).
 *
 * JavaScript runs one task at a time, so everything a tick callback does
 * before its first `await` runs before anything else can start.  The depth
 * counter raised around that synchronous stretch therefore names exactly the
 * requests the tick itself started.  A request started after the tick's
 * first await, or by anything else, reads as a normal load: the rule errs on
 * the side of the old behaviour.
 *
 * Kept apart from lib/poll.js so the client can read it even where a test
 * mocks the poller away.
 */
let depth = 0

/** Runs `fn` as a poll tick and returns whatever it returns. */
export function runPollTick(fn) {
  depth += 1
  try {
    return fn()
  } finally {
    depth -= 1
  }
}

/** Whether the code running right now was started by a poll tick. */
export function inPollTick() {
  return depth > 0
}
