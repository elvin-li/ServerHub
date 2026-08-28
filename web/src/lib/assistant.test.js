/**
 * Cmd+K catalog ranking — same scoring the backend uses for find.
 */
import { describe, expect, it } from 'vitest'
import { ASSISTANT_EVENT, matchCatalog, openAssistant } from './assistant'

const panels = [
  { id: 'containers', path: '/containers', title: 'Containers', aliases: ['docker', '容器'] },
  { id: 'logs', path: '/logs', title: '日志', aliases: ['日志', 'syslog'] },
  { id: 'dashboard', path: '/', title: '仪表盘', aliases: ['home'] },
]

describe('matchCatalog', () => {
  it('ranks a docker alias as containers', () => {
    expect(matchCatalog(panels, 'docker')[0].id).toBe('containers')
  })

  it('ranks a Chinese logs alias', () => {
    expect(matchCatalog(panels, '日志')[0].id).toBe('logs')
  })

  it('returns nothing for an empty needle', () => {
    expect(matchCatalog(panels, '   ')).toEqual([])
  })

  it('does not throw when aliases is a leftover mapping', () => {
    const hostile = [{ id: 'logs', path: '/logs', title: 'Logs', aliases: { 0: 'syslog' } }]
    expect(matchCatalog(hostile, 'syslog')).toEqual([])
    expect(matchCatalog(hostile, 'logs')[0].id).toBe('logs')
  })
})

describe('openAssistant', () => {
  it('dispatches a shell event with the given action', () => {
    const seen = []
    const onAssist = (event) => seen.push(event.detail)
    window.addEventListener(ASSISTANT_EVENT, onAssist)
    openAssistant({ action: 'page' })
    window.removeEventListener(ASSISTANT_EVENT, onAssist)
    expect(seen).toEqual([{ action: 'page' }])
  })
})
