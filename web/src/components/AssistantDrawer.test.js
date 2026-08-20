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
