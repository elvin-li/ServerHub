<!--
  Capsule on/off control shared by Shares service rows and Apps autostart.

  Those two surfaces used to drift: Shares already had a knob switch, Apps used
  a green checkbox plus On/Off labels. One control keeps the macOS/iOS look
  (accent track, no checkmark) and the same aria switch contract.
-->
<template>
  <button
    type="button"
    class="mac-switch"
    role="switch"
    :aria-checked="on ? 'true' : 'false'"
    :aria-label="$attrs['aria-label']"
    :disabled="disabled"
    @click.stop="onClick"
  ><span aria-hidden="true"></span></button>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  checked: { type: Boolean, default: undefined },
  modelValue: { type: Boolean, default: undefined },
  disabled: { type: Boolean, default: false },
})

const emit = defineEmits(['update:checked', 'update:modelValue', 'change'])

const on = computed(() => (props.modelValue ?? props.checked) === true)

function onClick() {
  if (props.disabled) return
  const next = !on.value
  emit('update:modelValue', next)
  emit('update:checked', next)
  emit('change', next)
}
</script>

<style scoped>
.mac-switch {
  position: relative;
  width: 38px;
  height: 22px;
  min-width: 38px;
  min-height: 22px;
  padding: 0;
  border: 0;
  border-radius: var(--radius-pill);
  background: #999;
  flex-shrink: 0;
  box-shadow: none;
}
.mac-switch span {
  position: absolute;
  top: 2px;
  left: 2px;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: #fff;
  box-shadow: 0 1px 3px rgba(0, 0, 0, .28);
  transition: transform .16s ease;
}
.mac-switch[aria-checked="true"] {
  background: var(--accent);
}
.mac-switch[aria-checked="true"] span {
  transform: translateX(16px);
}
.mac-switch:hover {
  filter: none;
  border-color: transparent;
}
.mac-switch:active {
  transform: none;
}
.mac-switch:disabled {
  cursor: not-allowed;
}
@media (prefers-reduced-motion: reduce) {
  .mac-switch span { transition: none; }
}
/* WCAG 2.5.8: 22px tall is under the 24px minimum for a fingertip. iOS sizes
   its own switch at 51x31, so growing towards that on touch is also the
   native look. Knob and travel scale with the track. */
@media (pointer: coarse) {
  .mac-switch {
    width: 44px;
    height: 26px;
    min-width: 44px;
    min-height: 26px;
  }
  .mac-switch span {
    width: 22px;
    height: 22px;
  }
  .mac-switch[aria-checked="true"] span { transform: translateX(18px); }
}
</style>
