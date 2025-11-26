42
const status = document.getElementById('status')
const packBtn = document.getElementById('packBtn')
const inputPath = document.getElementById('inputPath')
const cmdPath = document.getElementById('cmdPath')
const scPath = document.getElementById('scPath')
const srcPath = document.getElementById('srcPath')
const outPath = document.getElementById('outPath')
const fileMode = document.getElementById('file-mode')
const cmdMode = document.getElementById('cmd-mode')
const scMode = document.getElementById('sc-mode')
const srcMode = document.getElementById('src-mode')
const themeToggle = document.getElementById('themeToggle')
const remoteRow = document.getElementById('remoteRow')
const remotePath = document.getElementById('remotePath')

document.querySelectorAll('input[name="mode"]').forEach(r => {
  r.addEventListener('change', () => {
    const v = document.querySelector('input[name="mode"]:checked').value
    fileMode.classList.add('hidden'); cmdMode.classList.add('hidden'); scMode.classList.add('hidden'); srcMode.classList.add('hidden')
    if (v === 'file') fileMode.classList.remove('hidden')
    if (v === 'cmd') cmdMode.classList.remove('hidden')
    if (v === 'sc') scMode.classList.remove('hidden')
    if (v === 'src') srcMode.classList.remove('hidden')
  })
})

document.querySelectorAll('input[name="inj"]').forEach(r => {
  r.addEventListener('change', () => {
    const v = document.querySelector('input[name="inj"]:checked').value
    if (v === 'remote') remoteRow.classList.remove('hidden'); else remoteRow.classList.add('hidden')
  })
})

themeToggle.addEventListener('click', () => {
  const dark = document.documentElement.dataset.theme === 'dark'
  document.documentElement.dataset.theme = dark ? 'light' : 'dark'
})

packBtn.addEventListener('click', async () => {
  status.textContent = ''
  const mode = document.querySelector('input[name="mode"]:checked').value
  try {
    const out = outPath.value.trim()
    if (mode === 'cmd') {
      const cmd = cmdPath.value.trim()
      await window.__TAURI__.invoke('pack_cmd', { cmd, outPath: out })
    } else if (mode === 'file') {
      const inp = inputPath.value.trim()
      await window.__TAURI__.invoke('pack_file', { inputPath: inp, outPath: out })
    } else if (mode === 'sc') {
      const sc = scPath.value.trim()
      const inj = document.querySelector('input[name="inj"]:checked').value
      const remote = remotePath.value.trim()
      await window.__TAURI__.invoke('pack_shellcode', { scPath: sc, outPath: out, injMode: inj, remotePath: remote })
    } else if (mode === 'src') {
      const src = srcPath.value.trim()
      const lang = document.querySelector('input[name="lang"]:checked').value
      await window.__TAURI__.invoke('pack_source', { srcPath: src, outPath: out, lang })
    }
    status.textContent = '已生成: ' + out
  } catch (e) {
    status.textContent = '失败: ' + e
  }
})
