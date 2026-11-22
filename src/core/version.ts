import { z } from 'zod'

import packageJson from '../../package.json' with { type: 'json' }

/**
 * This release's version, fixed when the module loads: a daemon reports it, so a CLI from another release knows not
 * to talk to it. Read any later, an idle daemon would report the version of a package upgraded under it. A static
 * import (not a file read beside the source) is inlined by the bundler, so a program built with
 * `bun build --compile` reports it too.
 */
export const PACKAGE_VERSION = z.object({ version: z.string() }).parse(packageJson).version
