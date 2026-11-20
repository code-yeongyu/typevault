import {
  appendFileSync,
  closeSync,
  existsSync,
  fsyncSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  statSync,
} from 'node:fs'
import { basename, dirname, relative } from 'node:path'

import { z } from 'zod'

import { sha256Hex } from '../core/crypto'
import { canonicalJson, type Json, utf8 } from '../core/encoding'
import { TypeVaultError } from '../core/errors'
import { assertNoSymlinks, ensureDir } from '../core/fsx'
import { parseJsonText } from '../core/json-file'
import type { Layout } from '../core/layout'
import { withLock } from '../core/lock'

export type AuditMode = 'live' | 'sealed' | 'direct'

/** What happened, by whom. Metadata only: never a secret value. */
export type AuditEvent = {
  readonly action: string
  readonly mode: AuditMode
  readonly grant?: string
  readonly label?: string
  readonly tiers?: readonly string[]
  readonly entries?: readonly string[]
  readonly reason?: string
}

const RecordSchema = z.looseObject({ seq: z.number().int(), at: z.string(), prev: z.string(), hash: z.string() })
const AnchorSchema = z.object({ seq: z.number().int(), hash: z.string(), at: z.string() })
export type AuditRecord = z.infer<typeof RecordSchema>

const GENESIS = '0'.repeat(64)
const ANCHOR_EVERY = 100

const hashOf = (record: Readonly<Record<string, Json>>): string => sha256Hex(utf8(canonicalJson(record)))

function appendLine(path: string, line: string): void {
  const fd = openSync(path, 'a', 0o600)
  try {
    appendFileSync(fd, `${line}\n`)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
}

const TAIL_BYTES = 64 * 1024

/** The last record, read from the end of the log so an append never re-reads the whole trail. */
function readLast(layout: Layout): AuditRecord | undefined {
  if (!existsSync(layout.auditLog)) return undefined
  const size = statSync(layout.auditLog).size
  if (size > TAIL_BYTES) {
    const fd = openSync(layout.auditLog, 'r')
    try {
      const buffer = Buffer.alloc(TAIL_BYTES)
      readSync(fd, buffer, 0, TAIL_BYTES, size - TAIL_BYTES)
      const lines = buffer
        .toString('utf8')
        .split('\n')
        .filter((line) => line !== '')
      const last = lines.at(-1)
      if (lines.length > 1 && last !== undefined) return parseJsonText(layout.auditLog, last, RecordSchema)
    } finally {
      closeSync(fd)
    }
  }
  return readAudit(layout).at(-1)
}

export function readAudit(layout: Layout): readonly AuditRecord[] {
  if (!existsSync(layout.auditLog)) return []
  return readFileSync(layout.auditLog, 'utf8')
    .split('\n')
    .filter((line) => line !== '')
    .map((line) => parseJsonText(layout.auditLog, line, RecordSchema))
}

/** Another state-directory chain's anchors file beside `anchorsFile`, when `anchorsFile` is one. A vault has only one. */
function otherStateAnchors(anchorsFile: string): string | undefined {
  const name = basename(anchorsFile)
  const dir = dirname(anchorsFile)
  if (!name.startsWith('state-') || !existsSync(dir)) return undefined
  return readdirSync(dir).find((file) => file.startsWith('state-') && file.endsWith('.jsonl') && file !== name)
}

function writeAnchor(layout: Layout, anchorsFile: string, last: AuditRecord): void {
  assertInVault(layout, anchorsFile)
  ensureDir(dirname(anchorsFile))
  appendLine(anchorsFile, JSON.stringify({ seq: last.seq, hash: last.hash, at: last.at }))
}

// The anchors live in the committed vault: a pulled symlink there must not redirect a read or an append.
const assertInVault = (layout: Layout, anchorsFile: string): void =>
  assertNoSymlinks(dirname(layout.vault), relative(dirname(layout.vault), anchorsFile))

/**
 * The last checkpoint's seq, for catching up deferred ones. An anchors file it can't read or parse gives undefined
 * rather than throwing: this runs after the operation being audited took effect, checkpoint writes keep their own
 * checks, and verification reports the damage.
 */
function lastAnchoredSeq(layout: Layout, anchorsFile: string): number | undefined {
  try {
    assertInVault(layout, anchorsFile)
    if (!existsSync(anchorsFile)) return 0
    const last = readFileSync(anchorsFile, 'utf8').trimEnd().split('\n').at(-1)
    return last === undefined || last === '' ? 0 : AnchorSchema.parse(JSON.parse(last)).seq
  } catch {
    return undefined
  }
}

/**
 * Appends one hash-chained record; every 100th record's head is anchored in the (committable) vault. `anchorsFile` is
 * the one a validated vault state names. Without it, a state-directory chain has no trusted destination: the record
 * stays in the local log and its checkpoint waits for the next write that has one.
 */
export function appendAudit(layout: Layout, event: AuditEvent, anchorsFile = layout.fixedAnchorsFile): Promise<void> {
  return withLock(layout.auditLock, 'exclusive', async () => {
    ensureDir(layout.audit, 0o700)
    const last = readLast(layout)
    const fields = Object.fromEntries(Object.entries(event).filter(([, value]) => value !== undefined))
    const unhashed = { ...fields, seq: (last?.seq ?? 0) + 1, at: new Date().toISOString(), prev: last?.hash ?? GENESIS }
    const record = { ...unhashed, hash: hashOf(unhashed) }
    appendLine(layout.auditLog, JSON.stringify(record))
    if (anchorsFile === undefined) return
    const anchored = record.seq % ANCHOR_EVERY === 0 ? undefined : lastAnchoredSeq(layout, anchorsFile)
    const due = record.seq % ANCHOR_EVERY === 0 || (anchored !== undefined && record.seq - anchored >= ANCHOR_EVERY)
    if (due) writeAnchor(layout, anchorsFile, record)
  })
}

/** Anchors the current head now, in the anchors file a validated vault state names. */
export function anchorAudit(layout: Layout, anchorsFile = layout.fixedAnchorsFile): Promise<void> {
  return withLock(layout.auditLock, 'exclusive', async () => {
    const last = readAudit(layout).at(-1)
    if (anchorsFile === undefined || last === undefined) return
    writeAnchor(layout, anchorsFile, last)
  })
}

export type AuditVerdict =
  | { readonly ok: true; readonly records: number }
  | { readonly ok: false; readonly reason: string }

/**
 * Recomputes the chain and checks every anchor against it. A log too damaged to read fails the check. `anchorsFile`
 * defaults to the one owner.json names; pass the one a validated vault state names instead.
 */
export function verifyAudit(layout: Layout, anchorsFile = layout.anchorsFile): AuditVerdict {
  try {
    return verifyChain(layout, anchorsFile)
  } catch (error) {
    if (error instanceof TypeVaultError && error.code === 'tampered') return { ok: false, reason: error.message }
    throw error
  }
}

function verifyChain(layout: Layout, anchorsFile: string): AuditVerdict {
  // A vault's state-directory chain never changes name, so anchors under another name mean the owner history this
  // machine accepted (on first use) isn't the one they were made for: report it rather than skip anchors it can't check.
  // Only verification checks this, so a stray anchors file can't keep the vault from opening.
  const other = otherStateAnchors(anchorsFile)
  if (other !== undefined) return { ok: false, reason: `anchors exist for another audit chain (${other})` }
  const records = readAudit(layout)
  let prev = GENESIS
  const heads = new Map<number, string>()
  for (const record of records) {
    const { hash, ...unhashed } = record
    if (record.prev !== prev) return { ok: false, reason: `record ${record.seq} does not follow its predecessor` }
    if (hashOf(z.record(z.string(), z.json()).parse(unhashed)) !== hash) {
      return { ok: false, reason: `record ${record.seq} was modified` }
    }
    heads.set(record.seq, hash)
    prev = hash
  }
  const anchors = [layout.legacyAnchorsFile, anchorsFile].flatMap((file) =>
    existsSync(file)
      ? readFileSync(file, 'utf8')
          .split('\n')
          .filter((line) => line !== '')
          .map((line) => parseJsonText(file, line, AnchorSchema))
      : [],
  )
  const broken = anchors.find((anchor) => heads.get(anchor.seq) !== anchor.hash)
  if (broken !== undefined)
    return { ok: false, reason: `local log no longer matches the anchor at record ${broken.seq}` }
  return { ok: true, records: records.length }
}
