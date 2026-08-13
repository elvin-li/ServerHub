/**
 * The global error funnel: Vue render errors and unhandled promise rejections
 * must surface as one window event (which App.vue turns into a toast) plus a
 * console.error, instead of vanishing — or, as the old errorHandler did,
 * writing a hardcoded zh-CN string into a DOM node Vue owns.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { APP_ERROR_EVENT, installGlobalErrorHandlers, reportAppError } from './appError.js'

describe('installGlobalErrorHandlers', () => {
  let app
  let dispose
  let seen
  let onAppError
  let consoleError

  beforeEach(() => {
    app = { config: {} }
    seen = []
    onAppError = (event) => seen.push(event.detail)
    window.addEventListener(APP_ERROR_EVENT, onAppError)
    consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
    dispose = installGlobalErrorHandlers(app)
  })

  afterEach(() => {
    dispose?.()
    window.removeEventListener(APP_ERROR_EVENT, onAppError)
    consoleError.mockRestore()
  })

  it('routes Vue render errors to the app-error event and the console', () => {
    const boom = new Error('render exploded')
    expect(typeof app.config.errorHandler).toBe('function')

    app.config.errorHandler(boom, null, 'render')

    expect(seen).toHaveLength(1)
    expect(seen[0].error).toBe(boom)
    expect(seen[0].context).toBe('render')
    expect(consoleError).toHaveBeenCalledWith('[ServerHub]', 'render', boom)
  })

  it('surfaces unhandled promise rejections', () => {
    const reason = new Error('nobody caught me')
    const event = new Event('unhandledrejection', { cancelable: true })
    event.reason = reason
    const prevented = vi.spyOn(event, 'preventDefault')

    window.dispatchEvent(event)

    expect(seen).toHaveLength(1)
    expect(seen[0].error).toBe(reason)
    expect(seen[0].context).toBe('unhandledrejection')
    // We log it ourselves; the browser's duplicate default log is suppressed.
    expect(prevented).toHaveBeenCalled()
  })

  it('leaves stale-chunk rejections to chunkRecovery instead of toasting', () => {
    // lib/chunkRecovery.js answers these with a one-shot reload; a toast on top
    // of a reload that is already happening is only noise.
    const event = new Event('unhandledrejection', { cancelable: true })
    event.reason = new Error('Failed to fetch dynamically imported module: /assets/Apps-abc.js')
    const prevented = vi.spyOn(event, 'preventDefault')

    window.dispatchEvent(event)

    expect(seen).toHaveLength(0)
    expect(prevented).not.toHaveBeenCalled()
  })

  it('stops listening once disposed', () => {
    dispose()
    dispose = undefined

    const event = new Event('unhandledrejection', { cancelable: true })
    event.reason = new Error('late')
    window.dispatchEvent(event)

    expect(seen).toHaveLength(0)
  })
})

describe('reportAppError', () => {
  it('still logs when the event cannot be dispatched', () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
    const dispatch = vi.spyOn(window, 'dispatchEvent').mockImplementation(() => {
      throw new Error('no window for you')
    })

    expect(() => reportAppError(new Error('x'), 'render')).not.toThrow()
    expect(consoleError).toHaveBeenCalled()

    dispatch.mockRestore()
    consoleError.mockRestore()
  })
})
