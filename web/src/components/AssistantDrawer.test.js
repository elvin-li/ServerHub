/**
 * Contract tests for the shell AI drawer.
 *
 * The backend owns catalog matching and the Ollama call; this file only
 * checks that the two chips hit the right action and that a panel chip
 * navigates.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { ref } from 'vue'

vi.mock('../i18n', () => ({
  injectI18n: () => ({
    t: (key, params = {}) => Object.entries(params).reduce(
      (text, [name, value]) => text.replace(`{${name}}`, value),
      String(key),
    ),
    locale: ref('zh-CN'),
  }),
}))

vi.mock('../composables/useDismissable', () => ({ useDismissable: vi.fn() }))

vi.mock('../api/client', () => ({
  askAssistant: vi.fn(),
}))

vi.mock('vue-router', () => ({
  useRoute: () => ({ path: '/' }),
}))

const { askAssistant } = await import('../api/client')
const AssistantDrawer = (await import('./AssistantDrawer.vue')).default

function mountDrawer(props = {}) {
  return mount(AssistantDrawer, {
    props: { open: true, seed: '', ...props },
    global: {
      stubs: {
        'router-link': { template: '<a class="ollama-link"><slot /></a>' },
      },
    },
  })
}

describe('AssistantDrawer', () => {
  beforeEach(() => {
    askAssistant.mockReset()
    askAssistant.mockResolvedValue({
      ok: true,
      kind: 'brief',
      text: '负载正常',
      panels: [{ id: 'health', path: '/health', title: '健康检查' }],
      used_llm: false,
    })
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  it('does not render while closed', () => {
    const wrapper = mountDrawer({ open: false })
    expect(wrapper.find('[data-test="assistant-drawer"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('asks for a status brief without a typed question', async () => {
    const wrapper = mountDrawer()
    await wrapper.get('[data-test="assistant-brief"]').trigger('click')
    await flushPromises()
    expect(askAssistant).toHaveBeenCalledWith('', expect.objectContaining({
      action: 'brief',
      locale: 'zh-CN',
      path: '/',
    }))
    expect(wrapper.text()).toContain('负载正常')
    wrapper.unmount()
  })

  it('emits go when a suggested panel is clicked', async () => {
    const wrapper = mountDrawer()
    await wrapper.get('[data-test="assistant-brief"]').trigger('click')
    await flushPromises()
    const chip = wrapper.findAll('.assist-panels button')[0]
    await chip.trigger('click')
    expect(wrapper.emitted('go')[0]).toEqual(['/health'])
    expect(wrapper.emitted('close')).toBeTruthy()
    wrapper.unmount()
  })

  it('sends find with the typed panel name', async () => {
    askAssistant.mockResolvedValue({
      ok: true,
      kind: 'find',
      text: '找到这些面板：',
      panels: [{ id: 'logs', path: '/logs', title: '日志' }],
      used_llm: false,
    })
    const wrapper = mountDrawer()
    await wrapper.get('#assist-input').setValue('打开日志')
    await wrapper.get('form.assist-form').trigger('submit')
    await flushPromises()
    expect(askAssistant).toHaveBeenCalledWith('打开日志', expect.objectContaining({
      action: 'auto',
    }))
    expect(wrapper.text()).toContain('日志')
    wrapper.unmount()
  })

  it('explains the current route without a typed question', async () => {
    askAssistant.mockResolvedValue({
      ok: true,
      kind: 'page',
      text: 'Host overview and top CPU.',
      panels: [{ id: 'dashboard', path: '/', title: '仪表盘' }],
      used_llm: false,
    })
    const wrapper = mountDrawer()
    await wrapper.get('[data-test="assistant-page"]').trigger('click')
    await flushPromises()
    expect(askAssistant).toHaveBeenCalledWith('', expect.objectContaining({
      action: 'page',
      path: '/',
    }))
    expect(wrapper.text()).toContain('Host overview and top CPU.')
    wrapper.unmount()
  })

  it('does not clear a newer send when the previous ask finishes after close', async () => {
    let resolveFirst
    askAssistant.mockImplementationOnce(() => new Promise((resolve) => { resolveFirst = resolve }))
    const wrapper = mountDrawer()
    await wrapper.get('[data-test="assistant-brief"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="assistant-stop"]').exists()).toBe(true)
    await wrapper.setProps({ open: false })
    await flushPromises()
    await wrapper.setProps({ open: true })
    await flushPromises()
    let resolveSecond
    askAssistant.mockImplementationOnce(() => new Promise((resolve) => { resolveSecond = resolve }))
    await wrapper.get('[data-test="assistant-brief"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="assistant-stop"]').exists()).toBe(true)
    resolveFirst({
      ok: true,
      kind: 'brief',
      text: 'stale-brief',
      panels: [],
      used_llm: false,
    })
    await flushPromises()
    expect(wrapper.find('[data-test="assistant-stop"]').exists()).toBe(true)
    expect(wrapper.text()).not.toContain('stale-brief')
    resolveSecond({
      ok: true,
      kind: 'brief',
      text: 'fresh-brief',
      panels: [],
      used_llm: false,
    })
    await flushPromises()
    expect(wrapper.find('[data-test="assistant-stop"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('fresh-brief')
    wrapper.unmount()
  })

  it('renders a template brief with leftover Infinity/NaN as dashes, not the words', async () => {
    // A >4300-digit backend leftover arrives as Infinity after JSON.parse;
    // every sink already routes through finiteText/finiteN — pin it.
    askAssistant.mockResolvedValue({
      ok: true,
      kind: 'brief',
      text: '',
      used_llm: false,
      snapshot: {
        load: Infinity,
        cpu_load_pct: NaN,
        mem_used_pct: 10,
        disk_root_pct: 20,
        disk_root: '1/2 GB',
        uptime: '1.0 hours',
        engine_up: true,
        counts: { ok: Infinity, warn: 1, down: 0 },
        problems: [{ name: Infinity, state: 'down', detail: NaN }],
      },
      panels: [{ id: 'x', path: '/health', title: Infinity }],
    })
    const wrapper = mountDrawer()
    await wrapper.get('[data-test="assistant-brief"]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).not.toContain('Infinity')
    expect(wrapper.text()).not.toContain('NaN')
    expect(wrapper.text()).toContain('—')
    wrapper.unmount()
  })

  it('keeps the log a polite live region and distinguishes empty from a reply', async () => {
    const wrapper = mountDrawer()
    expect(wrapper.get('.assist-log').attributes('aria-live')).toBeUndefined()
    expect(wrapper.text()).toContain('assistant.empty')
    await wrapper.get('[data-test="assistant-brief"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('.assist-log').attributes('aria-live')).toBe('polite')
    expect(wrapper.text()).not.toContain('assistant.empty')
    wrapper.unmount()
  })

  it('shows the no-match message for a find miss instead of an empty reply', async () => {
    askAssistant.mockResolvedValue({
      ok: true,
      kind: 'find',
      text: 'No panel matches',
      panels: [],
      used_llm: false,
    })
    const wrapper = mountDrawer()
    await wrapper.get('#assist-input').setValue('no-such-panel')
    await wrapper.get('form.assist-form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('assistant.find_none')
    wrapper.unmount()
  })

  it('fail-closes a leftover mapping reply without throwing', async () => {
    askAssistant.mockResolvedValue({
      0: 'ghost',
      kind: ['find'],
      panels: { 0: { path: '/ghost', title: 'Ghost' } },
      text: { echo: 'nope' },
    })
    const wrapper = mountDrawer()
    await wrapper.get('[data-test="assistant-brief"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('.assist-panels').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('Ghost')
    wrapper.unmount()
  })

  it('null panel rows and a leftover mapping history log do not throw', async () => {
    askAssistant.mockResolvedValue({
      ok: true,
      kind: 'find',
      text: 'found',
      panels: [null, 'x', { path: '/logs', title: '日志' }],
      used_llm: false,
    })
    const wrapper = mountDrawer()
    wrapper.vm.turns = { 0: { role: 'user', content: 'stale' } }
    await wrapper.get('#assist-input').setValue('日志')
    await wrapper.get('form.assist-form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('日志')
    expect(askAssistant).toHaveBeenCalledWith('日志', expect.objectContaining({
      history: [],
    }))
    wrapper.unmount()
  })

  it('a leftover array ask body is treated as an empty reply, not a throw', async () => {
    askAssistant.mockResolvedValue(['brief'])
    const wrapper = mountDrawer()
    await wrapper.get('[data-test="assistant-brief"]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('assistant.empty_reply')
    wrapper.unmount()
  })

  it('stops an in-flight ask', async () => {
    askAssistant.mockImplementation((_query, opts) => new Promise((_resolve, reject) => {
      opts.signal.addEventListener('abort', () => {
        const err = new Error('cancelled')
        err.code = 'cancelled'
        reject(err)
      })
    }))
    const wrapper = mountDrawer()
    const pending = wrapper.get('[data-test="assistant-brief"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-test="assistant-stop"]').exists()).toBe(true)
    await wrapper.get('[data-test="assistant-stop"]').trigger('click')
    await pending
    await flushPromises()
    expect(wrapper.text()).toContain('assistant.cancelled')
    expect(wrapper.find('[data-test="assistant-stop"]').exists()).toBe(false)
    wrapper.unmount()
  })
})
