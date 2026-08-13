/**
 * Contract tests for the Ollama page.
 *
 * Everything runs against a mocked api/client — no live daemon:
 *   - the three page states (loaded sections / absent / failed first load),
 *   - the empty-state honesty rule (unreachable ≠ "no models"),
 *   - the poll contract (tick resolves false on a dead server, disposer runs
 *     on unmount, and the pull-log tail stops for good when the page dies).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

const polls = vi.hoisted(() => ({ callbacks: [], disposed: 0 }))

vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      String(key),
    ),
    locale: { value: 'en' },
    setLocale: vi.fn(),
  }),
}))

vi.mock('../lib/poll', () => ({
  startVisibleInterval: (fn) => {
    polls.callbacks.push(fn)
    return () => { polls.disposed += 1 }
  },
}))

vi.mock('../api/client', () => ({
  getOllamaStatus: vi.fn(),
  startOllamaPull: vi.fn(),
  getOllamaPullLog: vi.fn(),
  deleteOllamaModel: vi.fn(),
  unloadOllamaModel: vi.fn(),
  testOllamaModel: vi.fn(),
  doAction: vi.fn(),
}))

const {
  getOllamaStatus, getOllamaPullLog, startOllamaPull,
} = await import('../api/client')
const Ollama = (await import('./Ollama.vue')).default

/** The exact shape GET /api/ollama/status serves (hub/ollama_svc.status). */
const STATUS = {
  ts: '2026-08-14 04:20:00',
  url: 'http://127.0.0.1:11434',
  installed: true,
  binary: '/opt/homebrew/bin/ollama',
  reachable: true,
  version: '0.32.9',
  error: '',
  service: { label: 'com.kiro.ollama', loaded: true, running: true, pid: 42 },
  models: [{
    name: 'qwen3.5:4b',
    size: 3413361762,
    family: 'qwen35',
    parameter_size: '4.2B',
    quantization: 'Q4_K_M',
    context_length: 262144,
    capabilities: ['completion', 'tools', 'thinking', 'vision'],
    modified: '2026-08-13T20:27:24+08:00',
  }],
  resident: [{
    name: 'qwen3.5:4b',
    size: 3321207192,
    size_vram: 3321207192,
    context_length: 8192,
    expires_at: '2318-11-24T02:50:18+08:00',
    forever: true,
  }],
  pull: { running: false, rc: null, model: null, started: null, finished: null },
}

function mountPage() {
  return mount(Ollama, {
    global: {
      provide: { toast: vi.fn() },
      stubs: { RouterLink: true, SkeletonLoader: true, LoadFailure: true },
    },
  })
}

beforeEach(() => {
  polls.callbacks.length = 0
  polls.disposed = 0
  getOllamaStatus.mockReset()
  getOllamaPullLog.mockReset()
  startOllamaPull.mockReset()
})

describe('loaded page', () => {
  let wrapper

  afterEach(() => wrapper?.unmount())

  it('renders every section from one mocked status payload', async () => {
    getOllamaStatus.mockResolvedValue(STATUS)
    wrapper = mountPage()
    await flushPromises()
    const html = wrapper.html()

    // service card: label, version, badge, action buttons
    expect(html).toContain('com.kiro.ollama')
    expect(html).toContain('0.32.9')
    expect(html).toContain('ollama.state_running')
    expect(html).toContain('services.act_restart')
    // resident card: VRAM figure, keep_alive=-1 wording, unload
    expect(html).toContain('ollama.resident_title')
    expect(html).toContain('3.3 GB')
    expect(html).toContain('ollama.resident_forever')
    expect(html).toContain('ollama.act_unload')
    // installed models: quantization + capability badges + delete
    expect(html).toContain('ollama.models_title')
    expect(html).toContain('Q4_K_M')
    expect(html).toContain('thinking')
    expect(html).toContain('ollama.act_delete')
    // pull + quick test boxes
    expect(html).toContain('ollama.pull_title')
    expect(html).toContain('ollama.test_title')
    // no false claims while everything answered
    expect(html).not.toContain('ollama.absent_title')
    expect(html).not.toContain('ollama.daemon_unreachable')
  })

  it('preselects the first installed model for the quick test', async () => {
    getOllamaStatus.mockResolvedValue(STATUS)
    wrapper = mountPage()
    await flushPromises()
    expect(wrapper.find('select').element.value).toBe('qwen3.5:4b')
  })

  it('falls back to the thinking trace when the response is empty', async () => {
    // Real qwen3.5:4b behaviour under a capped num_predict: all tokens go to
    // reasoning, response is "" — the box must not look blank on success.
    getOllamaStatus.mockResolvedValue(STATUS)
    const { testOllamaModel } = await import('../api/client')
    testOllamaModel.mockResolvedValue({
      ok: true, model: 'qwen3.5:4b', response: '', thinking: 'pondering the greeting…',
      duration_s: 3.8, eval_count: 32, tokens_per_s: 23.4,
    })
    wrapper = mountPage()
    await flushPromises()

    await wrapper.find('input[aria-label="ollama.test_prompt_label"]').setValue('hi')
    const runButton = wrapper.findAll('button').find(b => b.text() === 'ollama.act_test')
    await runButton.trigger('click')
    await flushPromises()

    expect(testOllamaModel).toHaveBeenCalledWith('qwen3.5:4b', 'hi')
    const html = wrapper.html()
    expect(html).toContain('pondering the greeting…')
    expect(html).toContain('ollama.test_thinking_note')
  })
})

describe('degraded states', () => {
  let wrapper

  afterEach(() => wrapper?.unmount())

  it('shows the install path when ollama is absent, not empty tables', async () => {
    getOllamaStatus.mockResolvedValue({
      ...STATUS,
      installed: false,
      reachable: false,
      binary: null,
      version: '',
      service: { label: null, loaded: false, running: false, pid: null },
      models: [],
      resident: [],
    })
    wrapper = mountPage()
    await flushPromises()
    const html = wrapper.html()
    expect(html).toContain('ollama.absent_title')
    expect(html).toContain('to="/apps"')
    expect(html).not.toContain('ollama.models_empty')
  })

  it('blames the daemon when unreachable instead of claiming "no models"', async () => {
    getOllamaStatus.mockResolvedValue({
      ...STATUS, reachable: false, version: '', models: [], resident: [],
    })
    wrapper = mountPage()
    await flushPromises()
    const html = wrapper.html()
    expect(html).toContain('ollama.daemon_unreachable')
    expect(html).not.toContain('ollama.models_empty')
    expect(html).not.toContain('ollama.resident_empty')
  })

  it('surfaces a failed first load and drops the skeleton and empty states', async () => {
    getOllamaStatus.mockRejectedValue(new Error('backend unreachable'))
    wrapper = mountPage()
    await flushPromises()
    const html = wrapper.html()
    expect(html).toContain('load-failure')
    expect(html).not.toContain('ollama.absent_title')
    expect(html).not.toContain('skeleton-loader')
  })
})

describe('poll lifecycle', () => {
  it('registers one status poller whose tick reports a dead server', async () => {
    getOllamaStatus.mockRejectedValue(new Error('backend unreachable'))
    const wrapper = mountPage()
    await flushPromises()
    expect(polls.callbacks.length).toBe(1)
    expect(await polls.callbacks[0]()).toBe(false)
    wrapper.unmount()
  })

  it('reports success ticks so backoff resets', async () => {
    getOllamaStatus.mockResolvedValue(STATUS)
    const wrapper = mountPage()
    await flushPromises()
    expect(await polls.callbacks[0]()).toBe(true)
    wrapper.unmount()
  })

  it('disposes the status poller on unmount', async () => {
    getOllamaStatus.mockResolvedValue(STATUS)
    const wrapper = mountPage()
    await flushPromises()
    expect(polls.disposed).toBe(0)
    wrapper.unmount()
    expect(polls.disposed).toBe(1)
  })
})

describe('pull log tail', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  const flush = () => vi.advanceTimersByTimeAsync(0)

  //: Mount probes the (uncached) pull log once, so a pull started before the
  //: navigation resumes its tail; these fixtures answer that probe with "idle".
  const IDLE_LOG = { running: false, rc: null, model: null, log: '' }

  it('tails the log every 1.5s while the pull runs and stops on unmount', async () => {
    getOllamaStatus.mockResolvedValue(STATUS)
    startOllamaPull.mockResolvedValue({ running: true, model: 'llama3.2:3b' })
    getOllamaPullLog
      .mockResolvedValueOnce(IDLE_LOG) // the mount-time resume probe
      .mockResolvedValue({
        running: true, rc: null, model: 'llama3.2:3b', log: 'pulling manifest',
      })

    const wrapper = mountPage()
    await flush()
    expect(getOllamaPullLog).toHaveBeenCalledTimes(1)

    await wrapper.find('input[aria-label="ollama.pull_name_label"]').setValue('llama3.2:3b')
    const pullButton = wrapper.findAll('button').find(b => b.text() === 'ollama.act_pull')
    expect(pullButton).toBeTruthy()
    await pullButton.trigger('click')
    await flush()

    expect(startOllamaPull).toHaveBeenCalledWith('llama3.2:3b')
    expect(getOllamaPullLog).toHaveBeenCalledTimes(2)
    expect(wrapper.html()).toContain('pulling manifest')

    await vi.advanceTimersByTimeAsync(1500)
    expect(getOllamaPullLog).toHaveBeenCalledTimes(3)

    // Navigation away must kill the tail even though the pull keeps running.
    wrapper.unmount()
    await vi.advanceTimersByTimeAsync(1500 * 10)
    expect(getOllamaPullLog).toHaveBeenCalledTimes(3)
  })

  it('stops tailing once the pull reports finished and refreshes the list', async () => {
    getOllamaStatus.mockResolvedValue(STATUS)
    startOllamaPull.mockResolvedValue({ running: true, model: 'x:1' })
    getOllamaPullLog
      .mockResolvedValueOnce(IDLE_LOG) // the mount-time resume probe
      .mockResolvedValueOnce({ running: true, rc: null, model: 'x:1', log: 'pulling' })
      .mockResolvedValue({ running: false, rc: 0, model: 'x:1', log: 'success' })

    const wrapper = mountPage()
    await flush()
    const statusCallsAfterMount = getOllamaStatus.mock.calls.length

    await wrapper.find('input[aria-label="ollama.pull_name_label"]').setValue('x:1')
    const pullButton = wrapper.findAll('button').find(b => b.text() === 'ollama.act_pull')
    await pullButton.trigger('click')
    await flush()
    await vi.advanceTimersByTimeAsync(1500)

    expect(getOllamaPullLog).toHaveBeenCalledTimes(3)
    // Finished: the loop goes quiet and the model list is re-read.
    await vi.advanceTimersByTimeAsync(1500 * 10)
    expect(getOllamaPullLog).toHaveBeenCalledTimes(3)
    expect(getOllamaStatus.mock.calls.length).toBeGreaterThan(statusCallsAfterMount)
    expect(wrapper.html()).toContain('ollama.pull_done_ok')
    wrapper.unmount()
  })

  it('resumes the tail of a pull that was started before this navigation', async () => {
    getOllamaStatus.mockResolvedValue(STATUS)
    getOllamaPullLog.mockResolvedValue({
      running: true, rc: null, model: 'big:70b', log: 'pulling 42%',
    })

    const wrapper = mountPage()
    await flush()

    // No user action: the mount probe found a live pull and began tailing.
    expect(getOllamaPullLog).toHaveBeenCalledTimes(1)
    expect(wrapper.html()).toContain('pulling 42%')
    await vi.advanceTimersByTimeAsync(1500)
    expect(getOllamaPullLog).toHaveBeenCalledTimes(2)
    wrapper.unmount()
  })
})
