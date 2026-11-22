import { describe, expect, test } from 'bun:test'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import packageJson from '../../package.json' with { type: 'json' }

describe('PACKAGE_VERSION', () => {
  test('a program compiled with bun build --compile loads the daemon and reports the version', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'typevault-compiled-'))
    try {
      const entry = join(dir, 'entry.ts')
      const routes = JSON.stringify(join(import.meta.dir, '..', 'daemon', 'agent-routes.ts'))
      writeFileSync(
        entry,
        `import { agentRoutes } from ${routes}
const ping = agentRoutes({} as never)['/v1/ping']
const answer = await ping!(new Request('http://typevault/v1/ping', { method: 'POST' }))
process.stdout.write(JSON.stringify(await answer.json()))
`,
      )
      const outfile = join(dir, 'compiled')
      const build = await Bun.build({ entrypoints: [entry], compile: { outfile } })
      expect(build.success).toBe(true)
      const binary = existsSync(outfile) ? outfile : `${outfile}.exe`
      const run = Bun.spawn([binary], { stdout: 'pipe', stderr: 'pipe' })
      const [stdout, stderr, code] = await Promise.all([
        new Response(run.stdout).text(),
        new Response(run.stderr).text(),
        run.exited,
      ])
      expect(stderr).toBe('')
      expect(code).toBe(0)
      expect(JSON.parse(stdout)).toMatchObject({ ok: true, version: packageJson.version })
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }, 60_000)
})
