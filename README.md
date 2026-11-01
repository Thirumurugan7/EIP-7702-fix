# Chainwall Protocol

Solidity smart contracts and integration interfaces for the Chainwall protocol.

For a ready-to-use command-line interface, see the
[Chainwall CLI for Arbitrum](https://github.com/okcontract/chainwall-cli-arbitrum),
currently available in preview.

> [!IMPORTANT]
> This project is under review. We have completed an internal audit, and an external
> audit is ongoing. The external audit report is expected to be released in December
> 2026.

Chainwall is an onchain control plane for vaults, treasuries, and programmable
accounts. Its registry defines users, groups, capabilities, approved contracts,
and policies. Interact and MiniScript enforce those rules when executing actions.

## Repository contents

| Path | Contents |
| --- | --- |
| [src/](src/) | Tenant factories, registry, execution engine, accounts, and supporting contracts |
| [src/registry/](src/registry/) | Shared storage, capabilities, timelocks, and registry facets |
| [packages/interfaces/src/](packages/interfaces/src/) | Solidity integration interfaces and ABI types |
| [config/terms/chainwall-V2.md](config/terms/chainwall-V2.md) | Protocol terms and conditions |
| [doc/registry-containment.json](doc/registry-containment.json) | Registry selector inventory and pause policies |
| [foundry.toml](foundry.toml) | Compiler settings and build profiles |
| [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | Dependency revisions and license notices |

## Contract architecture

- [OKFactory](src/OKFactory.sol) creates each tenant stack in three stages using
  fixed [configuration](src/OKFactoryConfig.sol) and deployment modules. The
  Registry remains paused during construction and is handed to its intended
  owner when the stack is complete.
- [RegistryDiamond](src/RegistryDiamond.sol) holds directory, authority, and
  catalog state. Its [facets](src/registry/facets/) use namespaced storage and
  route sensitive changes through category-specific timelocks.
- [Interact](src/Interact.sol) coordinates proposals, approvals, and execution.
  Vault interactions run the [MiniScript engine](src/MiniScriptEngine.sol) in
  the vault's context. The [MiniScript host](src/MiniScript.sol) evaluates policy
  programs without granting them the vault's authority or native balance.
- [SafeFactory](src/SafeFactory.sol) and [AccountFactory](src/AccountFactory.sol)
  create tenant-bound Safes and native [OKAccount](src/OKAccount.sol) vaults.
  [OKGuard](src/OKGuard.sol) and [OKModule](src/OKModule.sol) connect managed
  Safes to the execution policy.
- [WebAuthnAuthAccountFactory](src/WebAuthnAuthAccountFactory.sol) and
  [WebAuthnAuthAccount](src/WebAuthnAuthAccount.sol) provide the optional
  passkey-based account authorization path.

## Governance

[RegistryTimelockFacet](src/registry/facets/RegistryTimelockFacet.sol) exposes
category and scope configuration, approvals, queue inspection, and execution.
Configure the governance policies and delays before delegating authority.

Group membership changes require the authority and review of every affected
capability and policy. Linked reviews execute the change atomically after all
requirements are satisfied; cancelling or expiring any review terminates its
bundle. `getActionBundle(actionId)` returns the independently reviewed records.
Queued capability grants and policy assignments bind the reviewed membership
revision, so later membership changes require renewed review.

Admins and `PAUSE_OPERATOR` actors can pause Registry writes; only admins can
resume them. Pause retains diagnostic reads and ordinary cancellation and expiry
cleanup. The selector inventory records the pause policy for each public surface.

Implementation and facet upgrades are governed by the tenant Registry and bind
reviewed code hashes and component relationships. Registry and facet transitions
are code-only. A successful code transition invalidates pending actions authorized
under earlier semantics. `freezeCuts()` permanently disables Registry facet cuts
and Registry UUPS upgrades.

## Building

Install Git, Foundry, and oksolc `0.8.36+oksolc.0.2.3`. Set `FOUNDRY_SOLC` to that
oksolc executable when building. [foundry.toml](foundry.toml) pins Solidity
`0.8.36` and the optimizer profiles; `FOUNDRY_SOLC` selects the compiler binary.
The accepted module hashes in [ProtocolCodehashes](src/ProtocolCodehashes.sol)
depend on the compiler and settings.

Initialize the production dependencies and the required nested OpenZeppelin
library from this repository's root:

```sh
git submodule update --init lib/openzeppelin-contracts-upgradeable lib/safe-contracts
git -C lib/openzeppelin-contracts-upgradeable submodule update --init lib/openzeppelin-contracts
```

Build with the default profile, or inspect release sizes with the production
profile:

```sh
FOUNDRY_SOLC=/path/to/oksolc forge build
FOUNDRY_SOLC=/path/to/oksolc FOUNDRY_PROFILE=production forge build --sizes
```

Both profiles use the IR optimizer and disable the bytecode metadata hash.
The production profile uses 800 optimizer runs. Build artifacts are written to `out/`.

## License and official factory deployments

OKcontract-owned code is licensed under [Business Source License 1.1](LICENSE).
Production use is permitted through **Official Factories and their unmodified
Covered Descendants**, as defined in the license. Official factories are identified
by chain ID and address in OKcontract's published deployment records. Other
production uses, including independently deployed copies, require a separate
license until the Change License takes effect. Non-production review, compilation,
modification, and auditing are permitted under the BUSL terms.

Each version converts to GPL-3.0-only on the fourth anniversary of its first
public distribution under BUSL-1.1. This is a source-available license, not an
Open Source license before conversion. Third-party components retain their own
licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
