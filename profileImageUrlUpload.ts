/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import dns from 'node:dns'
import http, { type IncomingMessage } from 'node:http'
import https from 'node:https'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:'])
const MAX_REDIRECTS = 5

function isLoopbackIPv4 (ip: string): boolean {
  return ip.split('.')[0] === '127'
}

function isBlockedIPv4 (ip: string): boolean {
  const parts = ip.split('.').map((p) => Number(p))
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true
  const [a, b, c] = parts
  if (a === 0) return true // "this" network
  if (a === 10) return true // private
  if (a === 127) return true // loopback
  if (a === 100 && b >= 64 && b <= 127) return true // CGNAT
  if (a === 169 && b === 254) return true // link-local (incl. cloud metadata)
  if (a === 172 && b >= 16 && b <= 31) return true // private
  if (a === 192 && b === 168) return true // private
  if (a === 192 && b === 0 && c === 0) return true // IETF protocol assignments
  if (a === 198 && (b === 18 || b === 19)) return true // benchmarking
  if (a >= 224) return true // multicast + reserved + broadcast
  return false
}

// Fully expands any valid IPv6 textual form (compressed "::", embedded dotted
// IPv4, zone id) into its 16 raw bytes. Classifying on bytes rather than on the
// textual form is required because the WHATWG URL parser re-serializes
// IPv4-mapped hosts in hex (e.g. "::ffff:169.254.169.254" -> "::ffff:a9fe:a9fe"),
// so a text/regex match on dotted-decimal alone is bypassable.
function ipv6ToBytes (ip: string): number[] | null {
  let s = ip.toLowerCase()
  const pct = s.indexOf('%')
  if (pct !== -1) s = s.slice(0, pct) // drop zone id
  const dc = s.split('::')
  if (dc.length > 2) return null
  const expand = (str: string): number[] => {
    if (str === '') return []
    const groups: number[] = []
    for (const seg of str.split(':')) {
      if (seg.includes('.')) {
        const o = seg.split('.').map((p) => Number(p))
        if (o.length !== 4 || o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return [NaN]
        groups.push((o[0] << 8) | o[1], (o[2] << 8) | o[3])
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(seg)) return [NaN]
        groups.push(parseInt(seg, 16))
      }
    }
    return groups
  }
  const head = expand(dc[0])
  const tail = dc.length === 2 ? expand(dc[1]) : []
  if (head.some(Number.isNaN) || tail.some(Number.isNaN)) return null
  let words: number[]
  if (dc.length === 2) {
    const missing = 8 - head.length - tail.length
    if (missing < 1) return null
    words = [...head, ...new Array<number>(missing).fill(0), ...tail]
  } else {
    words = head
  }
  if (words.length !== 8) return null
  const bytes: number[] = []
  for (const w of words) bytes.push((w >> 8) & 0xff, w & 0xff)
  return bytes
}

// Returns the embedded IPv4 (dotted) for every IPv6 form that carries an IPv4
// destination — mapped ::ffff:0:0/96, deprecated compatible ::/96, NAT64
// 64:ff9b::/96 and 6to4 2002::/16 — so those are classified by their IPv4 target.
function embeddedIPv4 (b: number[]): string | null {
  if (b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff) return `${b[12]}.${b[13]}.${b[14]}.${b[15]}`
  if (b.slice(0, 12).every((x) => x === 0) && !(b[12] === 0 && b[13] === 0 && b[14] === 0 && (b[15] === 0 || b[15] === 1))) return `${b[12]}.${b[13]}.${b[14]}.${b[15]}`
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) return `${b[12]}.${b[13]}.${b[14]}.${b[15]}`
  if (b[0] === 0x20 && b[1] === 0x02) return `${b[2]}.${b[3]}.${b[4]}.${b[5]}`
  return null
}

function isLoopbackIPv6 (ip: string): boolean {
  const b = ipv6ToBytes(ip)
  if (b == null) return false
  if (b.slice(0, 15).every((x) => x === 0) && b[15] === 1) return true // ::1
  const embedded = embeddedIPv4(b)
  return embedded != null && isLoopbackIPv4(embedded)
}

function isBlockedIPv6 (ip: string): boolean {
  const b = ipv6ToBytes(ip)
  if (b == null) return true
  const embedded = embeddedIPv4(b)
  if (embedded != null) return isBlockedIPv4(embedded)
  if (b.every((x) => x === 0)) return true // :: unspecified
  if (b.slice(0, 15).every((x) => x === 0) && b[15] === 1) return true // ::1 loopback
  if ((b[0] & 0xfe) === 0xfc) return true // fc00::/7 unique local
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true // fe80::/10 link-local
  if (b[0] === 0xff) return true // ff00::/8 multicast
  return false
}

function isBlockedAddress (ip: string): boolean {
  const family = net.isIP(ip)
  const blocked = family === 4 ? isBlockedIPv4(ip) : family === 6 ? isBlockedIPv6(ip) : true
  if (!blocked) return false
  // The local mock server used by the test suite is reached via loopback; permit it only there.
  const loopback = family === 4 ? isLoopbackIPv4(ip) : family === 6 ? isLoopbackIPv6(ip) : false
  if (loopback && process.env.NODE_ENV === 'test') return false
  return true
}

// Custom DNS lookup that both validates and pins the connected address. Because
// the address returned here is the exact one net/tls dials, there is no second,
// independent resolution to rebind against (closes the DNS-rebinding TOCTOU).
const validatingLookup: net.LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { ...(options as dns.LookupOptions), all: true }, (err, addresses) => {
    const cb = callback as (err: NodeJS.ErrnoException | null, address?: string | dns.LookupAddress[], family?: number) => void
    if (err != null) { cb(err); return }
    const list = (Array.isArray(addresses) ? addresses : [addresses]) as dns.LookupAddress[]
    const permitted = list.filter((a) => !isBlockedAddress(a.address))
    if (permitted.length === 0) {
      cb(new Error('Requested image URL resolves to a disallowed address'))
      return
    }
    if ((options as dns.LookupAllOptions)?.all === true) {
      cb(null, permitted)
    } else {
      cb(null, permitted[0].address, permitted[0].family)
    }
  })
}

// Fetches the image following redirects manually so that every hop is
// re-validated (closes the open-redirect bypass) and every connection is dialed
// only to an address that passed isBlockedAddress via validatingLookup.
async function fetchImage (rawUrl: unknown): Promise<IncomingMessage> {
  if (typeof rawUrl !== 'string') throw new Error('Requested image URL is not allowed')
  let currentUrl = new URL(rawUrl)
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    if (!ALLOWED_PROTOCOLS.has(currentUrl.protocol)) {
      throw new Error('Requested image URL is not allowed')
    }
    // For IP-literal hosts net/tls dials directly and never calls the custom
    // lookup, so classify them here (covers direct hits and redirects to a bare
    // IP such as the cloud metadata endpoint).
    const literalHost = currentUrl.hostname.replace(/^\[/, '').replace(/\]$/, '')
    if (net.isIP(literalHost) !== 0 && isBlockedAddress(literalHost)) {
      throw new Error('Requested image URL is not allowed')
    }
    const transport = currentUrl.protocol === 'https:' ? https : http
    const response = await new Promise<IncomingMessage>((resolve, reject) => {
      const request = transport.get(currentUrl, { lookup: validatingLookup }, resolve)
      request.on('error', reject)
    })
    const status = response.statusCode ?? 0
    const location = response.headers.location
    if (status >= 300 && status < 400 && location != null) {
      response.resume() // discard body before following the redirect
      currentUrl = new URL(location, currentUrl)
      continue
    }
    if (status !== 200) {
      response.resume()
      throw new Error('url returned a non-OK status code or an empty body')
    }
    return response
  }
  throw new Error('Requested image URL exceeded the redirect limit')
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetchImage(url)
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(response.pipe(fileStream))
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
