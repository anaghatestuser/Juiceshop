/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns'
import net from 'node:net'
import http from 'node:http'
import https from 'node:https'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// Blocks fetches aimed at loopback, private, link-local and other
// non-routable/reserved address ranges so a user-supplied imageUrl cannot be
// abused to make the server issue requests into internal-only network
// space (SSRF / CWE-918).
function isDisallowedIPv4 (address: string): boolean {
  const parts = address.split('.').map(Number)
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true
  const [a, b, c] = parts
  if (a === 0) return true // "this" network
  if (a === 10) return true // RFC1918
  if (a === 127) return true // loopback
  if (a === 100 && b >= 64 && b <= 127) return true // carrier-grade NAT
  if (a === 169 && b === 254) return true // link-local / cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true // RFC1918
  if (a === 192 && b === 0 && c === 2) return true // TEST-NET
  if (a === 192 && b === 168) return true // RFC1918
  if (a === 198 && (b === 18 || b === 19)) return true // benchmarking
  if (a >= 224) return true // multicast + reserved + broadcast
  return false
}

// Fully decodes an IPv6 literal into its 8 16-bit groups (resolving `::`
// compression and any trailing embedded dotted-decimal IPv4 form) instead of
// pattern-matching one specific textual spelling. Callers such as the WHATWG
// URL parser and `dns.lookup()` are free to render an IPv4-mapped/compatible
// address in different, equally valid textual forms (e.g. `::ffff:127.0.0.1`
// vs. its canonical compressed form `::ffff:7f00:1`); matching only one
// spelling lets the other slip past the check entirely, so the embedded
// IPv4 address is extracted from the parsed bits rather than the string.
function parseIPv6Groups (address: string): number[] | null {
  const zoneIdx = address.indexOf('%')
  const addr = zoneIdx === -1 ? address : address.slice(0, zoneIdx)

  const parseHextets = (part: string): number[] | null => {
    if (part === '') return []
    const tokens = part.split(':')
    const groups: number[] = []
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i]
      if (i === tokens.length - 1 && token.includes('.')) {
        const bytes = token.split('.').map(Number)
        if (bytes.length !== 4 || bytes.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null
        groups.push((bytes[0] << 8) | bytes[1])
        groups.push((bytes[2] << 8) | bytes[3])
      } else {
        if (!/^[0-9a-f]{1,4}$/i.test(token)) return null
        groups.push(parseInt(token, 16))
      }
    }
    return groups
  }

  const doubleColonIdx = addr.indexOf('::')
  if (doubleColonIdx !== -1) {
    if (addr.indexOf('::', doubleColonIdx + 1) !== -1) return null // more than one "::"
    const left = parseHextets(addr.slice(0, doubleColonIdx))
    const right = parseHextets(addr.slice(doubleColonIdx + 2))
    if (left === null || right === null) return null
    const missing = 8 - left.length - right.length
    if (missing < 0) return null
    return [...left, ...new Array(missing).fill(0), ...right]
  }
  const groups = parseHextets(addr)
  if (groups === null || groups.length !== 8) return null
  return groups
}

function groupsToIPv4 (high: number, low: number): string {
  return `${(high >>> 8) & 0xff}.${high & 0xff}.${(low >>> 8) & 0xff}.${low & 0xff}`
}

function isDisallowedIPv6 (address: string): boolean {
  const groups = parseIPv6Groups(address.toLowerCase())
  if (groups === null) return true // couldn't confidently parse it: fail closed
  if (groups.slice(0, 7).every((g) => g === 0) && (groups[7] === 0 || groups[7] === 1)) return true // :: and ::1
  if ((groups[0] & 0xffc0) === 0xfe80) return true // link-local fe80::/10
  if ((groups[0] & 0xfe00) === 0xfc00) return true // unique local fc00::/7
  const first5Zero = groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 && groups[4] === 0
  if (first5Zero && groups[5] === 0xffff) return isDisallowedIPv4(groupsToIPv4(groups[6], groups[7])) // ::ffff:0:0/96
  if (first5Zero && groups[5] === 0) return isDisallowedIPv4(groupsToIPv4(groups[6], groups[7])) // deprecated ::a.b.c.d /96
  if (groups[0] === 0x64 && groups[1] === 0xff9b && groups[2] === 0 && groups[3] === 0 && groups[4] === 0 && groups[5] === 0) {
    return isDisallowedIPv4(groupsToIPv4(groups[6], groups[7])) // NAT64 well-known prefix 64:ff9b::/96
  }
  return false
}

function isDisallowedAddress (address: string): boolean {
  if (net.isIPv4(address)) return isDisallowedIPv4(address)
  if (net.isIPv6(address)) return isDisallowedIPv6(address)
  return true // could not classify the resolved address: fail closed
}

// Custom `lookup` used for the *actual outbound connection* rather than as a
// separate pre-flight probe. `http(s).request()` invokes this exactly once,
// for the hostname it is about to connect to, and then connects to whatever
// address this callback returns -- there is no second, independent DNS
// resolution afterwards. That makes the validation and the connection use
// the very same resolved address, closing the DNS-rebinding TOCTOU window
// that exists when a hostname is checked with one lookup (e.g.
// `dns.lookup()`) and then handed to `fetch()`/`http.request()` to resolve
// and connect a second time.
function safeLookup (
  hostname: string,
  options: dns.LookupOptions | ((err: NodeJS.ErrnoException | null, address: string, family: number) => void),
  callback?: (err: NodeJS.ErrnoException | null, address: string, family: number) => void
): void {
  const cb = (typeof options === 'function' ? options : callback) as (err: NodeJS.ErrnoException | null, address: string, family: number) => void
  dns.lookup(hostname, { family: typeof options === 'object' ? options.family : undefined, all: false }, (err, address, family) => {
    if (err) {
      cb(err, '', 0)
      return
    }
    if (isDisallowedAddress(address)) {
      cb(new Error('imageUrl must not target internal or reserved network addresses'), '', 0)
      return
    }
    cb(null, address, family)
  })
}

// Rejects hostnames that are themselves a literal IP address in a
// disallowed range (e.g. `http://127.0.0.1/...`). The WHATWG URL parser
// already canonicalizes alternate IPv4 encodings (octal/hex/decimal/etc.)
// into dotted-decimal form, so checking `url.hostname` here also covers
// those obfuscation tricks. Literal IPs never trigger the `lookup` callback
// above (Node connects to them directly, skipping DNS), so they must be
// checked explicitly at this layer.
function rejectDisallowedLiteralAddress (hostname: string): void {
  const stripped = hostname.replace(/^\[|\]$/g, '')
  if (net.isIP(stripped) !== 0 && isDisallowedAddress(stripped)) {
    throw new Error('imageUrl must not target internal or reserved network addresses')
  }
}

interface SimpleResponse {
  ok: boolean
  status: number
  body: ReadableStream<Uint8Array> | null
}

// Performs the request manually (instead of using `fetch`) so that both the
// initial hostname and every redirect hop are connected to through
// `safeLookup`, which validates the exact address that gets connected to
// rather than a separately-resolved stand-in for it.
async function fetchPublicUrl (initialUrl: string): Promise<SimpleResponse> {
  let currentUrl: URL
  try {
    currentUrl = new URL(initialUrl)
  } catch {
    throw new Error('imageUrl is not a valid URL')
  }

  for (let redirects = 0; redirects <= 5; redirects++) {
    if (currentUrl.protocol !== 'http:' && currentUrl.protocol !== 'https:') {
      throw new Error('imageUrl must use the http or https protocol')
    }
    if (currentUrl.hostname === '') {
      throw new Error('imageUrl must not target internal or reserved network addresses')
    }
    rejectDisallowedLiteralAddress(currentUrl.hostname)

    const transport = currentUrl.protocol === 'https:' ? https : http
    const response = await new Promise<http.IncomingMessage>((resolve, reject) => {
      const req = transport.request(currentUrl, { lookup: safeLookup }, resolve)
      req.on('error', reject)
      req.end()
    })

    const status = response.statusCode ?? 0
    if (status >= 300 && status < 400 && response.headers.location) {
      response.resume() // drain & discard the redirect response body
      currentUrl = new URL(response.headers.location, currentUrl)
      continue
    }

    return {
      ok: status >= 200 && status < 300,
      status,
      body: Readable.toWeb(response) as unknown as ReadableStream<Uint8Array>
    }
  }
  throw new Error('imageUrl caused too many redirects')
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetchPublicUrl(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
