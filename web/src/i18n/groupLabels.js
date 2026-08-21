/**
 * Yaml inventory group ids → i18n keys.
 *
 * Stored group names on this host are Chinese strings in services.yaml.
 * Only 智能家居 is mapped; other headings stay as stored text.
 */
export const GROUP_I18N_KEYS = {
  '智能家居': 'groups.smart_home', // cjk-input: yaml inventory group id
}

export function groupI18nKey(name) {
  if (typeof name !== 'string' || !name) return ''
  return GROUP_I18N_KEYS[name] || ''
}
