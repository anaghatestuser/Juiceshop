/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Injectable, inject } from '@angular/core'
import { type Backup } from '../Models/backup.model'
import { CookieService } from 'ngy-cookie'

import { SnackBarHelperService } from './snack-bar-helper.service'
import { MatSnackBar } from '@angular/material/snack-bar'
import { firstValueFrom, forkJoin, from, of } from 'rxjs'
import { ChallengeService } from './challenge.service'

@Injectable({
  providedIn: 'root'
})
export class LocalBackupService {
  private readonly cookieService = inject(CookieService)
  private readonly challengeService = inject(ChallengeService)
  private readonly snackBarHelperService = inject(SnackBarHelperService)
  private readonly snackBar = inject(MatSnackBar)

  private readonly VERSION = 1
  private readonly SIGNATURE_KEY_STORAGE = 'owasp-juice-shop-backup-key'
  private signatureKey?: Uint8Array

  async save (fileName = 'owasp_juice_shop'): Promise<void> {
    const backup: Backup = { version: this.VERSION }

    backup.banners = {
      welcomeBannerStatus: this.cookieService.get('welcomebanner_status') ? this.cookieService.get('welcomebanner_status') : undefined,
      cookieConsentStatus: this.cookieService.get('cookieconsent_status') ? this.cookieService.get('cookieconsent_status') : undefined
    }
    backup.language = this.cookieService.get('language') ? this.cookieService.get('language') : undefined

    try {
      const [continueCode, continueCodeFindIt, continueCodeFixIt] = await firstValueFrom(forkJoin([
        this.challengeService.continueCode(),
        this.challengeService.continueCodeFindIt(),
        this.challengeService.continueCodeFixIt()
      ]))
      backup.continueCode = continueCode
      backup.continueCodeFindIt = continueCodeFindIt
      backup.continueCodeFixIt = continueCodeFixIt
    } catch {
      console.log('Failed to retrieve continue code(s) for backup from server. Using cookie values as fallback.')
      backup.continueCode = this.cookieService.get('continueCode') ? this.cookieService.get('continueCode') : undefined
      backup.continueCodeFindIt = this.cookieService.get('continueCodeFindIt') ? this.cookieService.get('continueCodeFindIt') : undefined
      backup.continueCodeFixIt = this.cookieService.get('continueCodeFixIt') ? this.cookieService.get('continueCodeFixIt') : undefined
    }

    backup.signature = this.computeSignature(backup)

    const blob = new Blob([JSON.stringify(backup)], { type: 'text/plain;charset=utf-8' })
    this.saveFile(blob, `${fileName}-${new Date().toISOString().split('T')[0]}.json`)
  }

  saveFile (blob: Blob, fileName: string) {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = fileName
    a.click()
    URL.revokeObjectURL(url)
  }

  restore (backupFile: File) {
    return from(backupFile.text().then((backupData) => {
      const backup: Backup = JSON.parse(backupData)

      if (backup.version === this.VERSION) {
        if (!this.isValidBackup(backup)) {
          this.snackBarHelperService.open('Backup file contains invalid data and could not be restored.', 'errorBar')
          return
        }
        this.restoreCookie('welcomebanner_status', backup.banners?.welcomeBannerStatus)
        this.restoreCookie('cookieconsent_status', backup.banners?.cookieConsentStatus)
        this.restoreCookie('language', backup.language)
        this.restoreCookie('continueCodeFindIt', backup.continueCodeFindIt)
        this.restoreCookie('continueCodeFixIt', backup.continueCodeFixIt)
        this.restoreCookie('continueCode', backup.continueCode)

        const snackBarRef = this.snackBar.open('Backup has been restored from ' + backupFile.name, 'Apply changes now', {
          duration: 10000,
          panelClass: ['mat-body']
        })
        snackBarRef.onAction().subscribe(() => {
          const hackingProgress = backup.continueCode ? this.challengeService.restoreProgress(encodeURIComponent(backup.continueCode)) : of(true)
          const findItProgress = backup.continueCodeFindIt ? this.challengeService.restoreProgressFindIt(encodeURIComponent(backup.continueCodeFindIt)) : of(true)
          const fixItProgress = backup.continueCodeFixIt ? this.challengeService.restoreProgressFixIt(encodeURIComponent(backup.continueCodeFixIt)) : of(true)
          forkJoin([hackingProgress, findItProgress, fixItProgress]).subscribe({
            next: () => {
              location.reload()
            },
            error: (err) => { console.log(err) }
          })
        })
      } else {
        this.snackBarHelperService.open(`Version ${backup.version} is incompatible with expected version ${this.VERSION}`, 'errorBar')
      }
    }).catch((err: Error) => {
      this.snackBarHelperService.open(`Backup restore operation failed: ${err.message}`, 'errorBar')
    }))
  }

  private readonly supportedLanguages = ['ar_SA', 'az_AZ', 'bg_BG', 'bn_BD', 'ca_ES', 'cs_CZ', 'da_DK', 'de_CH', 'de_DE', 'el_GR', 'en', 'es_ES', 'et_EE', 'fa_IR', 'fi_FI', 'fr_FR', 'ga_IE', 'he_IL', 'hi_IN', 'hu_HU', 'id_ID', 'it_IT', 'ja_JP', 'ka_GE', 'ko_KR', 'lv_LV', 'my_MM', 'nl_NL', 'no_NO', 'pl_PL', 'pt_BR', 'pt_PT', 'ro_RO', 'ru_RU', 'si_LK', 'sv_SE', 'th_TH', 'tr_TR', 'uk_UA', 'zh_CN', 'zh_HK', 'zh_TW']

  private readonly continueCodePattern = /^[a-zA-Z0-9]+$/

  private readonly cookieConsentStates = ['dismiss', 'allow', 'deny']

  private isValidBackup (backup: Backup): boolean {
    if (backup.language !== undefined && (typeof backup.language !== 'string' || !this.supportedLanguages.includes(backup.language))) {
      return false
    }
    for (const continueCode of [backup.continueCode, backup.continueCodeFindIt, backup.continueCodeFixIt]) {
      if (continueCode !== undefined && (typeof continueCode !== 'string' || !this.continueCodePattern.test(continueCode))) {
        return false
      }
    }
    if (backup.banners !== undefined) {
      if (backup.banners === null || typeof backup.banners !== 'object' || Array.isArray(backup.banners)) {
        return false
      }
      if (backup.banners.welcomeBannerStatus !== undefined && backup.banners.welcomeBannerStatus !== 'dismiss') {
        return false
      }
      if (backup.banners.cookieConsentStatus !== undefined && !this.cookieConsentStates.includes(backup.banners.cookieConsentStatus)) {
        return false
      }
    }
    return true
  }

  private restoreCookie (cookieName: string, cookieValue: string) {
    if (cookieValue) {
      const expires = new Date()
      expires.setFullYear(expires.getFullYear() + 1)
      this.cookieService.put(cookieName, cookieValue, { expires })
    } else {
      this.cookieService.remove(cookieName)
    }
  }
}
