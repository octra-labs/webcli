# XNS-1: Xpectrum NFT Standard

XNS-1 is a non-fungible token standard for octra, the counterpart to the OCS01 token
standard. it ships as the `nft` contract template: a pure interface
(`interfaces/IXNS1.aml`) plus a reference implementation (`main.aml`).

token ids are 0-indexed, so the first mint is id 0. every value-like field is `u128`.
authorization uses `caller`, never `origin`. the supply invariant
`sum(balances) == total_supply` holds across mint and transfer.

## interface

| function | purpose |
|---|---|
| `mint(to, creator, metadata_uri, royalty_bps)` | owner mints a new token, returns its id |
| `transfer(to, token_id)` | owner moves their own token |
| `transfer_from(from, to, token_id)` | approved address or operator moves a token |
| `approve(approved, token_id)` | grant single-token transfer rights |
| `revoke_approval(token_id)` | clear the per-token approval |
| `set_operator(operator, approved)` | grant or revoke an account-wide operator |
| `transfer_ownership(new_owner)` | hand the contract owner role to another address |
| `set_provenance_hash(hash)` | commit a one-way provenance hash (settable once) |
| `add_circle_resource(token_id, uri, access)` | attach a circle resource pointer, returns its id |
| `set_circle_resource(token_id, resource_id, uri, access)` | update an existing resource |
| `clear_circle_resource(token_id, resource_id)` | deactivate a resource |
| `owner_of(token_id)` | current owner |
| `creator_of(token_id)` | original creator |
| `royalty_of(token_id)` | royalty in basis points (max 1000 = 10%) |
| `token_uri(token_id)` | metadata uri |
| `balance_of(addr)` | number of tokens held |
| `get_approved(token_id)` | the approved address, if any |
| `is_approved_or_owner(token_id, addr)` | whether addr may move the token |
| `total_supply()` | number of tokens minted |
| `symbol()` | collection symbol |
| `get_provenance_hash()` | the committed provenance hash |
| `token_circle_count(token_id)` | number of circle resources on a token |
| `token_circle_uri(token_id, resource_id)` | a single resource uri |

## packed views

three views return pipe-delimited strings for indexers and wallets:

```
get_token_info(id)             >> id | owner | creator | name | royalty_bps | minted_epoch | uri
get_token_circle_info(id, rid) >> token_id | resource_id | uri | access | active | version
get_contract_info()            >> name | symbol | total_supply | owner
```

## circle resources

a token may carry one or more circle resource pointers alongside its `token_uri`. each
pointer is a uri (usually an `oct://...` reference to on-chain content) plus an `access`
hint. `access` is a non-authoritative client hint, currently `public` or `sealed_read`;
the contract stores pointers only and does not enforce circle access policy.
