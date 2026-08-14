// E2E client for the live-export WebSocket server, using Node's built-in
// RFC 6455 WebSocket implementation (what the browser site client uses).
// Expects an initial snapshot on connect plus a few broadcasts:
//   node tools/ws_client_e2e.mjs [port] [expected payload file]

import { readFileSync } from 'node:fs'

const port = process.argv[2] ?? '23313'
const expected = process.argv[3]
  ? readFileSync(process.argv[3], 'utf8')
  : '{"format":"ZOD","version":1,"source":"ZZZ Packet Capture","characters":null,"discs":null,"wengines":null}'

let got = 0
const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`)
const timeout = setTimeout(() => {
  console.error('TIMEOUT: expected at least 3 messages')
  process.exit(1)
}, 15000)

ws.onopen = () => console.log('connected')
ws.onerror = (e) => {
  console.error('websocket error:', e.message ?? e)
  process.exit(1)
}
ws.onmessage = (ev) => {
  got++
  const data = typeof ev.data === 'string' ? ev.data : new TextDecoder().decode(ev.data)
  if (data !== expected) {
    console.error(`PAYLOAD MISMATCH on message ${got}`)
    console.error(`expected: ${expected.slice(0, 120)}`)
    console.error(`received: ${data.slice(0, 120)}`)
    process.exit(1)
  }
  console.log(`message ${got} ok (${data.length} bytes)`)
  if (got >= 3) {
    clearTimeout(timeout)
    ws.close()
    console.log('TEST PASSED')
    process.exit(0)
  }
}