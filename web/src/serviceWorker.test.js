import { describe, expect, it, vi } from 'vitest'

import { registerServiceWorker } from './serviceWorker.js'

function eventTarget(extra = {}) {
  const listeners = new Map()
  return {
    ...extra,
    addEventListener: vi.fn((name, handler) => listeners.set(name, handler)),
    emit(name) { listeners.get(name)?.() },
  }
}

function harness({ controlled = true, waiting = false } = {}) {
  const worker = eventTarget({ state: 'installing' })
  const waitingWorker = waiting ? { postMessage: vi.fn() } : null
  const registration = eventTarget({
    installing: worker,
    waiting: waitingWorker,
    update: vi.fn().mockResolvedValue(undefined),
  })
  const serviceWorker = eventTarget({
    controller: controlled ? {} : null,
    register: vi.fn().mockResolvedValue(registration),
  })
  return { registration, serviceWorker, waitingWorker, worker }
}

describe('service worker updates', () => {
  it('does nothing when service workers are unavailable', async () => {
    await expect(registerServiceWorker({ serviceWorker: null })).resolves.toBeNull()
  })

  it('does not reload a page during its first service worker install', async () => {
    const { serviceWorker } = harness({ controlled: false })
    const reload = vi.fn()

    await registerServiceWorker({ serviceWorker, reload })
    serviceWorker.emit('controllerchange')

    expect(serviceWorker.register).toHaveBeenCalledWith('/sw.js')
    expect(reload).not.toHaveBeenCalled()
  })

  it('never reloads on controllerchange; the update banner owns the refresh', async () => {
    const { serviceWorker } = harness()
    const reload = vi.fn()

    await registerServiceWorker({ serviceWorker, reload })
    serviceWorker.emit('controllerchange')
    serviceWorker.emit('controllerchange')

    expect(reload).not.toHaveBeenCalled()
  })

  it('activates a worker that was already waiting when the page loaded', async () => {
    const { waitingWorker, serviceWorker } = harness({ waiting: true })

    await registerServiceWorker({ serviceWorker })

    expect(waitingWorker.postMessage).toHaveBeenCalledWith('skipWaiting')
  })

  it('announces an installed update only to an already-controlled tab', async () => {
    const { registration, serviceWorker, worker } = harness()
    const dispatchUpdate = vi.fn()

    await registerServiceWorker({ serviceWorker, dispatchUpdate })
    registration.emit('updatefound')
    worker.state = 'installed'
    worker.emit('statechange')

    expect(dispatchUpdate).toHaveBeenCalledTimes(1)
  })

  it('checks for updates when a long-lived tab regains focus', async () => {
    const { registration, serviceWorker } = harness()
    const windowTarget = eventTarget()
    let clock = 1_000

    await registerServiceWorker({
      serviceWorker,
      windowTarget,
      documentTarget: null,
      now: () => clock,
      updateCheckInterval: 60_000,
    })
    windowTarget.emit('focus')
    expect(registration.update).not.toHaveBeenCalled()

    clock += 60_000
    windowTarget.emit('focus')
    await Promise.resolve()
    expect(registration.update).toHaveBeenCalledTimes(1)

    windowTarget.emit('focus')
    expect(registration.update).toHaveBeenCalledTimes(1)
  })

  it('checks for updates when a hidden tab becomes visible again', async () => {
    const { registration, serviceWorker } = harness()
    const documentTarget = eventTarget({ visibilityState: 'hidden' })
    let clock = 1_000

    await registerServiceWorker({
      serviceWorker,
      windowTarget: null,
      documentTarget,
      now: () => clock,
      updateCheckInterval: 60_000,
    })
    clock += 60_000
    documentTarget.emit('visibilitychange')
    expect(registration.update).not.toHaveBeenCalled()

    documentTarget.visibilityState = 'visible'
    documentTarget.emit('visibilitychange')
    await Promise.resolve()
    expect(registration.update).toHaveBeenCalledTimes(1)
  })
})
