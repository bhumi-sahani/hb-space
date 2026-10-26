-- HB Space — Phase 3, migration 4: key-possession proof for key envelopes (finding F2).
--
-- WHY: after Phase 2, any signed-in member session (including a stolen one)
-- could overwrite the wrapped vault key envelopes and lock everyone out. This
-- migration makes every envelope write require proof that the writer has
-- actually unlocked the vault, not just signed in.
--
-- HOW: the client derives  proof = HKDF-SHA-256(VMK, "hbspace/key-proof/v1" || vault_id)
-- and stores only  key_verifier = SHA-256(proof)  on each envelope. Every INSERT or
-- UPDATE by a vault member must carry key_proof such that SHA-256(key_proof) equals
-- the vault's verifier. The proof is checked and then discarded (never stored).
-- Neither value reveals the VMK; the verifier is a hash of a 256-bit secret, so it
-- cannot be brute-forced.
--
-- ADDITIVE ONLY: no existing table, policy, grant, or function is changed or dropped.
-- Adds two columns, two constraints, one trigger, and column-level grants.
-- RLS policies are untouched: membership is still required by the existing policies.

-- ---------------------------------------------------------------------------
-- Safety check: this migration assumes no envelopes exist yet (Phase 2 never
-- created real ones; the verification script always rolls back). If rows exist,
-- stop without changing anything so they can be inspected by hand.
-- ---------------------------------------------------------------------------
do $precheck$
begin
  if exists (select 1 from public.vault_key_envelopes) then
    raise exception 'vault_key_envelopes already contains rows. Stop: inspect them before applying the key-proof migration (see SECURITY_ARCHITECTURE.md §6.7).';
  end if;
end
$precheck$;

alter table public.vault_key_envelopes
  -- SHA-256 of the key-possession proof. Same value on every envelope of a vault.
  add column key_verifier bytea not null
    constraint vault_key_envelopes_key_verifier_len check (octet_length(key_verifier) = 32),
  -- Write-only channel for the proof. The trigger always clears it, and this
  -- constraint guarantees no proof is ever persisted.
  add column key_proof bytea
    constraint vault_key_envelopes_key_proof_never_stored check (key_proof is null);

comment on column public.vault_key_envelopes.key_verifier is 'SHA-256 of the VMK key-possession proof. Not secret; immutable.';
comment on column public.vault_key_envelopes.key_proof is 'Write-only: checked by trigger, then discarded. Always null when stored.';

-- ---------------------------------------------------------------------------
-- Trigger: enforce the proof for vault members.
--
-- SECURITY DEFINER so it can lock the vault row (serialising concurrent first
-- inserts) and read every envelope of the vault regardless of RLS. It takes no
-- arguments and can only run as a trigger. Non-members are passed through
-- untouched so the existing RLS policies reject them exactly as before.
-- (The project owner in the SQL editor has no auth.uid() and is not checked;
-- the owner already bypasses RLS.)
-- ---------------------------------------------------------------------------
create function private.enforce_vault_key_proof()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  existing_verifier bytea;
begin
  if not private.is_vault_member(new.vault_id) then
    return new; -- RLS (unchanged) rejects non-members.
  end if;

  if new.key_proof is null or octet_length(new.key_proof) <> 32 then
    raise exception 'a valid vault key proof is required to write key envelopes'
      using errcode = 'insufficient_privilege';
  end if;

  if tg_op = 'INSERT' then
    perform 1 from public.vaults where id = new.vault_id for update;

    select e.key_verifier into existing_verifier
    from public.vault_key_envelopes e
    where e.vault_id = new.vault_id
    limit 1;

    if existing_verifier is null then
      -- First envelope of the vault: it establishes the verifier, and must prove it.
      if pg_catalog.sha256(new.key_proof) <> new.key_verifier then
        raise exception 'key proof does not match the declared verifier'
          using errcode = 'insufficient_privilege';
      end if;
    else
      if new.key_verifier is distinct from existing_verifier
         or pg_catalog.sha256(new.key_proof) <> existing_verifier then
        raise exception 'key proof does not match this vault'
          using errcode = 'insufficient_privilege';
      end if;
    end if;
  else
    if new.key_verifier is distinct from old.key_verifier then
      raise exception 'the key verifier cannot be changed'
        using errcode = 'insufficient_privilege';
    end if;
    if pg_catalog.sha256(new.key_proof) <> old.key_verifier then
      raise exception 'key proof does not match this vault'
        using errcode = 'insufficient_privilege';
    end if;
  end if;

  new.key_proof := null;
  return new;
end;
$$;

revoke all on function private.enforce_vault_key_proof() from public;

-- Fires before vault_key_envelopes_stamp (triggers run in name order); both are BEFORE ROW.
create trigger vault_key_envelopes_proof
  before insert or update on public.vault_key_envelopes
  for each row execute function private.enforce_vault_key_proof();

-- ---------------------------------------------------------------------------
-- Column grants (additive). key_verifier can be set on insert only; key_proof
-- can be supplied on insert and update. No other privilege changes.
-- ---------------------------------------------------------------------------
grant insert (key_verifier, key_proof) on table public.vault_key_envelopes to authenticated;
grant update (key_proof) on table public.vault_key_envelopes to authenticated;
