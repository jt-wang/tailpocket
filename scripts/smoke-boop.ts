// Boop's Pocket (src/pocket.ts) on the real TailPocket helper, the local network only, and the Go test
// phone: scripts/smoke-downstream.sh copies this into a copy of Boop's tree and runs it there.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Pocket } from '../src/pocket.ts'

const phone = process.env.TAILPOCKET_PHONE!

/** One `tailpocket-phone dial`: its exit code, stdout and stderr. A dial that has not ended in 30 s, or
 *  ends by a signal, fails the test: it is neither an answer nor a refusal. */
const dial = (link: string) => new Promise<{ code: number; out: string; err: string }>((resolve, reject) => {
  const child = spawn(phone, ['dial', '-routes', 'lan', '-link', link])
  let out = '', err = ''
  child.stdout.on('data', (d) => { out += d })
  child.stderr.on('data', (d) => { err += d })
  const timer = setTimeout(() => { child.kill(); reject(new Error(`dial still running after 30 s: ${err}`)) }, 30_000)
  child.on('error', (e) => { clearTimeout(timer); reject(e) })
  child.on('exit', (code, signal) => {
    clearTimeout(timer)
    if (code === null) reject(new Error(`dial ended by ${signal}: ${err}`))
    else resolve({ code, out, err })
  })
  child.stdin.end('ping\n')
})

test('Boop pairs two phones over the local network; removing one device turns only that phone away as revoked', { timeout: 180_000 }, async () => {
  const bot = createServer((s) => s.once('data', (d) => s.end(`hello ${d.toString().trim()} from boop\n`)))
  await new Promise<void>((r) => bot.listen(0, '127.0.0.1', r))
  const dir = mkdtempSync(join(tmpdir(), 'boop-smoke-'))
  const pocket = await Pocket.open({ statePath: join(dir, 'tailpocket.json'), forward: `127.0.0.1:${(bot.address() as { port: number }).port}`, name: 'smoke', routes: ['lan'] })
  try {
    const pair = async (n: number) => {
      let emoji: string[] = []
      const w = await pocket.window(`code-${n}`, 120, { ask: (a) => { emoji = a.emoji; w.confirm(true) }, askEnded() {} })
      assert.match(w.qr, /^tailpocket2:/)
      const link = join(dir, `link-${n}.json`)
      await promisify(execFile)(phone, ['pair', '-routes', 'lan', '-device', `smoke phone ${n}`, '-out', link, w.qr], { timeout: 60_000 })
      assert.equal(emoji.length, 4, 'the person saw four emoji')
      await pocket.claimed(`code-${n}`, `device-${n}`)
      return link
    }
    const one = await pair(1), two = await pair(2)
    for (const link of [one, two]) assert.deepEqual(await dial(link), { code: 0, out: 'hello ping from boop\n', err: '' })

    await pocket.deviceRevoked('device-1')
    const removed = await dial(one)
    assert.equal(removed.out, '', 'a removed device still reached Boop')
    assert.equal(removed.code, 1)
    // The computer said so over the encrypted session (connectphone.ErrRevoked), not a helper that is gone.
    assert.match(removed.err, /no longer has this phone paired/, `removed device: ${removed.err}`)
    assert.deepEqual(await dial(two), { code: 0, out: 'hello ping from boop\n', err: '' }, 'the other phone lost Boop: the helper stopped, or revoked it too')
  } finally {
    await pocket.close()
    bot.close()
    rmSync(dir, { recursive: true, force: true })
  }
})
