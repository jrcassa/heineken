import { open } from 'sqlite'
import sqlite3 from 'sqlite3'
import { mkdir, stat, rm } from 'fs/promises'
import { join } from 'path'
import { proto } from '../../WAProto'
import { initAuthCreds } from './auth-utils'
import { BufferJSON } from './generics'
import { AuthenticationCreds, AuthenticationState, SignalDataTypeMap } from '../Types'
import logger from './logger'


export const useSQLiteAuthState = async (
  folder: string
): Promise<{ state: AuthenticationState; saveCreds: () => Promise<void> }> => {
  const dbPath = join(folder, 'db.sqlite')

  const folderInfo = await stat(folder).catch(() => undefined)
  if (!folderInfo) await mkdir(folder, { recursive: true })

  const db = await open({ filename: dbPath, driver: sqlite3.Database })

  await db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA temp_store = MEMORY;
    PRAGMA mmap_size = 30000000000;
  `)

  await db.exec(`
    CREATE TABLE IF NOT EXISTS auth_data (
      key TEXT PRIMARY KEY,
      value TEXT
    );
  `)


  const insertStmt = await db.prepare(
    `INSERT OR REPLACE INTO auth_data (key, value) VALUES (?, ?)`
  )
  const deleteStmt = await db.prepare(`DELETE FROM auth_data WHERE key = ?`)
  const writeData = async (key: string, data: any) => {
    const value = JSON.stringify(data, BufferJSON.replacer)
    await insertStmt.run(key, value)
  }

  const readData = async (key: string) => {
    const row = await db.get(`SELECT value FROM auth_data WHERE key = ?`, [key])
    if (!row) return null
    try {
      return JSON.parse(row.value, BufferJSON.reviver)
    } catch {
      return null
    }
  }

  const removeData = async (key: string) => {
    await deleteStmt.run(key)
  }

  const creds: AuthenticationCreds = (await readData('creds')) || initAuthCreds()

  return {
    state: {
      creds,
      keys: {
        get: async (type, ids) => {
          const data: { [_: string]: SignalDataTypeMap[typeof type] } = {}
          await Promise.all(
            ids.map(async (id) => {
              let value = await readData(`${type}-${id}`)
              if (type === 'app-state-sync-key' && value) {
                value = proto.Message.AppStateSyncKeyData.fromObject(value)
              }
              data[id] = value
            })
          )
          return data
        },
        set: async (data) => {
          await db.exec('BEGIN TRANSACTION')
          try {
            for (const category in data) {
              for (const id in data[category]) {
                const value = data[category][id]
                const key = `${category}-${id}`
                if (value) await writeData(key, value)
                else await removeData(key)
              }
            }
            await db.exec('COMMIT')
          } catch (e) {
            await db.exec('ROLLBACK')
            throw e
          }
        }
      }
    },
    saveCreds: async () => {
      await writeData('creds', creds)
    }
  }
}
export const deleteSQLiteAuthState = async (folder: string): Promise<void> => {
  try {
    await rm(folder, { recursive: true, force: true })
    logger.trace(`🗑️ Diretório de sessão removido: ${folder}`)
  } catch (err) {
    logger.error(`❌ Erro ao remover diretório da sessão: ${folder}`, err)
  }
}

