# Third-party notices

The [BUSL-1.1 license](LICENSE) covers the OKcontract-owned Chainwall work.
Third-party components retain their own licenses; the Chainwall production-use
grant does not restrict rights granted by those licenses.

The source dependencies are pinned by Git submodules. License copies accompany
this release. The nested OpenZeppelin revision is pinned by its parent submodule.

| Component | Pinned revision | License |
| --- | --- | --- |
| OpenZeppelin Contracts Upgradeable | `60b305a8f3ff0c7688f02ac470417b6bbf1c4d27` | [MIT](LICENSES/openzeppelin-contracts-upgradeable-LICENSE) |
| OpenZeppelin Contracts (nested dependency used by `@openzeppelin/contracts/`) | `e4f70216d759d8e6a64144a9e1f7bbeed78e7079` | [MIT](LICENSES/openzeppelin-contracts-LICENSE) |
| Safe contracts | `dc437e8fba8b4805d76bcbd1c668c9fd3d1e83be` | [LGPL-3.0](LICENSES/safe-contracts-LICENSE) |

The [GPLv3 text](LICENSES/GPL-3.0-only.txt) is included both as the Chainwall
Change License and as the text incorporated by LGPLv3. Preserve dependency
copyright and license notices when redistributing source or compiled code.
Individual upstream files may carry additional notices that remain applicable.

Foundry and oksolc are separately installed build tools and are not distributed
here.
