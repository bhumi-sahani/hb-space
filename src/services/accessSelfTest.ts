import type { SupabaseClient } from '@supabase/supabase-js'

/**
 * Live authorization self-test, run from a real signed-in session against the
 * real Supabase project. Complements supabase/tests/rls_verification.sql, which
 * impersonates roles in SQL; this one goes through the actual Data API and
 * Storage API with the actual JWT.
 *
 * Every probe that SHOULD be refused reports FAIL if it succeeds (and tries to
 * undo any effect). The member round trip uploads random placeholder bytes,
 * never media, and deletes them afterwards.
 */

export type ProbeOutcome = 'pass' | 'fail' | 'skip'

export interface ProbeResult {
  name: string
  outcome: ProbeOutcome
  detail?: string
}

const BUCKET = 'private-media'

function randomHex(bytes: number): string {
  const buf = crypto.getRandomValues(new Uint8Array(bytes))
  return '\\x' + Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('')
}

function randomBlob(bytes: number): { blob: Blob; data: Uint8Array } {
  const data = crypto.getRandomValues(new Uint8Array(bytes))
  return { blob: new Blob([data], { type: 'application/octet-stream' }), data }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index])
}

async function probe(results: ProbeResult[], name: string, run: () => Promise<ProbeResult['outcome'] | [ProbeOutcome, string]>) {
  try {
    const outcome = await run()
    results.push(Array.isArray(outcome) ? { name, outcome: outcome[0], detail: outcome[1] } : { name, outcome })
  } catch {
    results.push({ name, outcome: 'fail', detail: 'Unexpected error while running this check.' })
  }
}

export async function runAccessSelfTest(client: SupabaseClient, vaultId: string | null): Promise<ProbeResult[]> {
  const results: ProbeResult[] = []
  const { data: userData } = await client.auth.getUser()
  const userId = userData.user?.id
  if (!userId) return [{ name: 'Signed-in session', outcome: 'fail', detail: 'No valid session.' }]

  const targetVault = vaultId ?? crypto.randomUUID()

  // ---- Checks for every account ------------------------------------------------
  await probe(results, 'Cannot add anyone to the vault', async () => {
    const { error } = await client.from('vault_members').insert({ vault_id: targetVault, user_id: userId })
    return error ? 'pass' : ['fail', 'Membership insert was accepted.']
  })

  await probe(results, 'Cannot remove vault memberships', async () => {
    const { data, error } = await client.from('vault_members').delete().eq('user_id', userId).select()
    return error || (data ?? []).length === 0 ? 'pass' : ['fail', 'Membership delete was accepted.']
  })

  await probe(results, 'Cannot add media to another vault', async () => {
    const { error } = await client.from('media_items').insert({
      id: crypto.randomUUID(),
      vault_id: crypto.randomUUID(),
      format_version: 1,
      wrapped_dek: randomHex(60),
      encrypted_meta: randomHex(284),
      ciphertext_size: 64,
    })
    return error ? 'pass' : ['fail', 'Insert into a foreign vault was accepted.']
  })

  await probe(results, 'Cannot replace key envelopes of another vault', async () => {
    const { data, error } = await client
      .from('vault_key_envelopes')
      .update({ iv: randomHex(12) })
      .eq('vault_id', crypto.randomUUID())
      .select()
    return error || (data ?? []).length === 0 ? 'pass' : ['fail', 'Foreign envelope update was accepted.']
  })

  await probe(results, 'Cannot upload to a guessed storage path', async () => {
    const path = `${targetVault}/${crypto.randomUUID()}`
    const { error } = await client.storage.from(BUCKET).upload(path, randomBlob(64).blob, {
      contentType: 'application/octet-stream',
      upsert: false,
    })
    if (error) return 'pass'
    await client.storage.from(BUCKET).remove([path])
    return ['fail', 'Upload to a path without a media record was accepted.']
  })

  await probe(results, 'Cannot download a guessed storage path', async () => {
    const { data, error } = await client.storage.from(BUCKET).download(`${targetVault}/${crypto.randomUUID()}`)
    return error || !data ? 'pass' : ['fail', 'Download of a guessed path returned data.']
  })

  if (!vaultId) {
    // ---- Non-member: must see nothing at all ------------------------------------
    await probe(results, 'Cannot list vault storage', async () => {
      const { data, error } = await client.storage.from(BUCKET).list()
      return error || (data ?? []).length === 0 ? 'pass' : ['fail', 'Storage listing returned entries to a non-member.']
    })

    for (const table of ['vaults', 'vault_members', 'vault_key_envelopes', 'media_items']) {
      await probe(results, `Sees no rows in ${table}`, async () => {
        const { data, error } = await client.from(table).select('*').limit(1)
        if (error) return 'pass' // refused outright is also acceptable
        return (data ?? []).length === 0 ? 'pass' : ['fail', `${table} returned data to a non-member.`]
      })
    }
    return results
  }

  // ---- Member: key envelopes need the key-possession proof (Phase 3, finding F2) ----
  // Harmless by construction: it writes back the envelope's own, unchanged IV and sends
  // no proof. With the protection in place the server refuses; without it, the stored
  // key material would still be byte-for-byte identical (only `revision` would change).
  await probe(results, 'Cannot rewrite vault key envelopes with only a login session', async () => {
    const { data: rows, error: readError } = await client
      .from('vault_key_envelopes')
      .select('kind, iv, key_verifier')
      .eq('vault_id', vaultId)
      .limit(1)
    if (readError) return ['fail', 'Key envelopes could not be read; the Phase 3 migration may not be applied.']
    const row = (rows ?? [])[0] as { kind?: unknown; iv?: unknown } | undefined
    if (!row || typeof row.kind !== 'string' || typeof row.iv !== 'string') {
      return ['skip', 'No vault key exists yet. Run this again after setting up the vault.']
    }
    const { data, error } = await client
      .from('vault_key_envelopes')
      .update({ iv: row.iv })
      .eq('vault_id', vaultId)
      .eq('kind', row.kind)
      .select('kind')
    if (error) return 'pass'
    return (data ?? []).length === 0
      ? ['fail', 'Unexpected result: the update matched no rows.']
      : ['fail', 'A key envelope update without the key proof was accepted. Apply migration 20261022120000_vault_key_proof.sql.']
  })

  // ---- Member: full placeholder round trip --------------------------------------
  const itemId = crypto.randomUUID()
  const objectPath = `${vaultId}/${itemId}`
  const payload = randomBlob(64)
  let rowCreated = false
  let objectCreated = false
  let itemReady = false
  const folderId = crypto.randomUUID()
  let folderCreated = false

  await probe(results, 'Can create a pending media record (server sets uploader and path)', async () => {
    const { data, error } = await client
      .from('media_items')
      .insert({
        id: itemId,
        vault_id: vaultId,
        format_version: 1,
        has_thumbnail: false,
        wrapped_dek: randomHex(60),
        encrypted_meta: randomHex(284),
        ciphertext_size: payload.data.length,
      })
      .select('uploaded_by, status, object_path')
      .single()
    if (error || !data) return ['fail', 'Insert was refused.']
    rowCreated = true
    const row = data as { uploaded_by: string; status: string; object_path: string }
    if (row.uploaded_by !== userId || row.status !== 'pending' || row.object_path !== objectPath) {
      return ['fail', 'Server did not enforce uploader/status/path.']
    }
    return 'pass'
  })

  if (rowCreated) {
    await probe(results, 'Cannot mark ready before the object is uploaded', async () => {
      const { error } = await client.from('media_items').update({ status: 'ready' }).eq('id', itemId)
      return error ? 'pass' : ['fail', 'Item was marked ready without an object.']
    })

    await probe(results, 'Can upload the encrypted object for own pending record', async () => {
      const { error } = await client.storage.from(BUCKET).upload(objectPath, payload.blob, {
        contentType: 'application/octet-stream',
        upsert: false,
      })
      if (error) return ['fail', 'Upload was refused.']
      objectCreated = true
      return 'pass'
    })

    if (objectCreated) {
      await probe(results, 'Cannot overwrite an existing object', async () => {
        const { error } = await client.storage.from(BUCKET).upload(objectPath, randomBlob(64).blob, {
          contentType: 'application/octet-stream',
          upsert: true,
        })
        return error ? 'pass' : ['fail', 'Overwrite (upsert) was accepted.']
      })

      await probe(results, 'Can mark own upload ready', async () => {
        const { data, error } = await client.from('media_items').update({ status: 'ready' }).eq('id', itemId).select('status')
        if (!error && (data ?? []).length === 1) {
          itemReady = true
          return 'pass'
        }
        return ['fail', 'Finalise was refused.']
      })

      await probe(results, 'Can download the object and it is unchanged', async () => {
        const { data, error } = await client.storage.from(BUCKET).download(objectPath)
        if (error || !data) return ['fail', 'Download was refused.']
        const downloaded = new Uint8Array(await data.arrayBuffer())
        return sameBytes(downloaded, payload.data) ? 'pass' : ['fail', 'Downloaded bytes differ from uploaded bytes.']
      })

      await probe(results, 'Storage listing shows the object only by its random name', async () => {
        const { data, error } = await client.storage.from(BUCKET).list(vaultId, { search: itemId })
        if (error) return ['fail', 'Listing was refused for a member.']
        const names = (data ?? []).map((entry) => entry.name)
        return names.length === 1 && names[0] === itemId ? 'pass' : ['fail', 'Listing did not match the expected object.']
      })

      await probe(results, 'Cannot attach a thumbnail to an item declared without one', async () => {
        const { error } = await client.storage.from(BUCKET).upload(`${objectPath}.t`, randomBlob(32).blob, {
          contentType: 'application/octet-stream',
          upsert: false,
        })
        if (error) return 'pass'
        await client.storage.from(BUCKET).remove([`${objectPath}.t`])
        return ['fail', 'Thumbnail upload was accepted.']
      })
    }
  }

  // ---- Phase 4 (migration 5): folders, trash, organising --------------------------
  // Uses a throwaway folder with a random (undecryptable) name blob; it is deleted below.
  await probe(results, 'Can create a folder (opaque id and encrypted name only)', async () => {
    const { data, error } = await client
      .from('media_folders')
      .insert({ id: folderId, vault_id: vaultId, parent_id: null, encrypted_meta: randomHex(284) })
      .select('created_by, depth')
      .single()
    if (error || !data) {
      return error?.code === 'PGRST205' || error?.code === '42P01'
        ? ['fail', 'Folders table missing. Apply migration 20261023120000_folders_trash.sql.']
        : ['fail', 'Folder insert was refused.']
    }
    folderCreated = true
    const row = data as { created_by: string; depth: number }
    return row.created_by === userId && row.depth === 0 ? 'pass' : ['fail', 'Server did not stamp the folder creator/depth.']
  })

  if (folderCreated) {
    await probe(results, 'Cannot re-parent a folder', async () => {
      const { error } = await client.from('media_folders').update({ parent_id: crypto.randomUUID() }).eq('id', folderId)
      return error ? 'pass' : ['fail', 'Folder structure change was accepted.']
    })
  }

  if (itemReady) {
    await probe(results, 'Can move an item to the trash and restore it (server-stamped time)', async () => {
      const trashed = await client.from('media_items').update({ trashed_at: '2000-01-01T00:00:00Z' }).eq('id', itemId).select('trashed_at')
      const stamp = (trashed.data?.[0] as { trashed_at?: string } | undefined)?.trashed_at
      if (trashed.error || !stamp) return ['fail', 'Moving to the trash was refused.']
      if (new Date(stamp).getUTCFullYear() <= 2000) return ['fail', 'The client chose the trash time.']
      const restored = await client.from('media_items').update({ trashed_at: null }).eq('id', itemId).select('trashed_at')
      return !restored.error && (restored.data ?? []).length === 1 ? 'pass' : ['fail', 'Restore was refused.']
    })

    await probe(results, "Organising cannot change an item's encrypted data", async () => {
      const { error } = await client.from('media_items').update({ encrypted_meta: randomHex(284) }).eq('id', itemId)
      return error ? 'pass' : ['fail', 'Encrypted metadata was overwritten.']
    })

    if (folderCreated) {
      await probe(results, 'Cannot delete a folder that still holds an item', async () => {
        const moved = await client.from('media_items').update({ folder_id: folderId }).eq('id', itemId).select('id')
        if (moved.error || (moved.data ?? []).length !== 1) return ['fail', 'Moving the item into the folder was refused.']
        const { error } = await client.from('media_folders').delete().eq('id', folderId)
        await client.from('media_items').update({ folder_id: null }).eq('id', itemId)
        if (error) return 'pass'
        folderCreated = false
        return ['fail', 'A non-empty folder was deleted.']
      })
    }
  }

  // ---- Cleanup (always attempted) ---------------------------------------------------
  if (objectCreated) {
    await probe(results, 'Can delete the object (cleanup)', async () => {
      const { data, error } = await client.storage.from(BUCKET).remove([objectPath])
      return !error && (data ?? []).length === 1 ? 'pass' : ['fail', 'Object could not be deleted; remove it from the dashboard.']
    })
  }
  if (rowCreated) {
    await probe(results, 'Can delete the record (cleanup)', async () => {
      const { data, error } = await client.from('media_items').delete().eq('id', itemId).select('id')
      return !error && (data ?? []).length === 1 ? 'pass' : ['fail', 'Record could not be deleted; remove it from the dashboard.']
    })
  }
  if (folderCreated) {
    await probe(results, 'Can delete the empty test folder (cleanup)', async () => {
      const { data, error } = await client.from('media_folders').delete().eq('id', folderId).select('id')
      return !error && (data ?? []).length === 1 ? 'pass' : ['fail', 'Test folder could not be deleted; it shows as "Unreadable folder". Delete it in the app.']
    })
  }

  return results
}
