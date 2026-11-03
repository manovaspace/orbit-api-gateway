# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1](https://github.com/manovaspace/orbit-api-gateway/compare/v0.3.0...v0.3.1) (2026-11-03)


### Bug Fixes

* **build:** pin sibling modules and report the real version ([#53](https://github.com/manovaspace/orbit-api-gateway/issues/53)) ([d343f81](https://github.com/manovaspace/orbit-api-gateway/commit/d343f81d9c85a749e2c2510735b5ff6e346fcdef))

## [0.3.0](https://github.com/manovaspace/orbit-api-gateway/compare/v0.2.0...v0.3.0) (2026-11-03)


### Features

* **flags:** proxy the platform flag document on the public edge ([#51](https://github.com/manovaspace/orbit-api-gateway/issues/51)) ([d9ab29f](https://github.com/manovaspace/orbit-api-gateway/commit/d9ab29f66479b6398ca71c871490737ec5716745))

## [0.2.0](https://github.com/manovaspace/orbit-api-gateway/compare/v0.1.0...v0.2.0) (2026-11-03)


### Features

* **orgs:** REST routes for sign-up, organizations and invites ([#44](https://github.com/manovaspace/orbit-api-gateway/issues/44)) ([3645200](https://github.com/manovaspace/orbit-api-gateway/commit/3645200fde6860aafdae3c499a8eaaf7597b6417))

## 0.1.0 (2026-11-02)


### Features

* accept mobile identifier on password login ([#20](https://github.com/manovaspace/orbit-api-gateway/issues/20)) ([f9c1828](https://github.com/manovaspace/orbit-api-gateway/commit/f9c1828031edf3542854de14c0bcf107d0f0729a))
* **gateway:** add admin owner challenge and developer onboarding claim REST routes ([eb90197](https://github.com/manovaspace/orbit-api-gateway/commit/eb901977173396c4652d13851fb114badc686a5d))
* **gateway:** adopt canonical /dev and /system REST routes with backward-compatible aliases ([cd9b38a](https://github.com/manovaspace/orbit-api-gateway/commit/cd9b38a79de33ff0ea03fcfd8636d7cc3a3e283d))
* **gateway:** embed and serve canonical installer on GET / and /install.sh ([562b355](https://github.com/manovaspace/orbit-api-gateway/commit/562b35571a0bdc0087081640de72770cf8650936))
* **installer:** sync canonical install.sh for v0.4.5 with binary symlinks ([2081840](https://github.com/manovaspace/orbit-api-gateway/commit/208184037088ff33039029d3618697dae27ff8cb))
* **installer:** sync canonical install.sh for v0.4.6 with automatic legacy alias cleanup ([aa164a0](https://github.com/manovaspace/orbit-api-gateway/commit/aa164a01362a8db7dfeb5ce040b66b1814957d23))
* publish JWKS for product token verification ([#21](https://github.com/manovaspace/orbit-api-gateway/issues/21)) ([e927357](https://github.com/manovaspace/orbit-api-gateway/commit/e92735742d4f6c9543c7123baa5f55d129cd147d))


### Bug Fixes

* **ci:** restore valid v2 golangci config schema ([4f6bdd1](https://github.com/manovaspace/orbit-api-gateway/commit/4f6bdd165d6b0154939fda81f4347e8e424aaa2a))
* **ci:** tidy go modules ([ceda344](https://github.com/manovaspace/orbit-api-gateway/commit/ceda344573b909dfb4c2fb7381906d5421ea77fb))
* **deps:** tidy go.mod against current orbit siblings ([05596cb](https://github.com/manovaspace/orbit-api-gateway/commit/05596cbbbca9867c30466be2d7f70b3159c98137))
* **deps:** tidy go.mod against current orbit siblings ([4a34b08](https://github.com/manovaspace/orbit-api-gateway/commit/4a34b087b652fd36ea0aef86487c458c46a11fb7))
* **install:** check PATH before exec ([56a5cfc](https://github.com/manovaspace/orbit-api-gateway/commit/56a5cfc14d9373f47bdb09a2b17a3e8abc32fce5))
* **lint:** silence errcheck in tests, remove unused helpers, and modernize strings.Title ([4a38a5c](https://github.com/manovaspace/orbit-api-gateway/commit/4a38a5c9ed4f8627d07e43a1d97469ebe57b11a2))
* pin Go 1.26.10 for crypto/x509 advisory ([b49fdd3](https://github.com/manovaspace/orbit-api-gateway/commit/b49fdd3ee8a7ec34b5323efc49887fce19580748))
* tidy go.mod so CI can build ([3a900ec](https://github.com/manovaspace/orbit-api-gateway/commit/3a900ecf62cf059ad7b436c66f3bf52cde2290a4))


### Code Refactoring

* adopt the Go service standard ([#31](https://github.com/manovaspace/orbit-api-gateway/issues/31)) ([7aecac0](https://github.com/manovaspace/orbit-api-gateway/commit/7aecac009f34213364e789c9e1be15cfb1082a9a))
* **gateway:** serve installer strictly on root GET / ([0ed280d](https://github.com/manovaspace/orbit-api-gateway/commit/0ed280de79e1589892a0657a4c21aa14f8f4fb5a))

## [Unreleased]

### Added

- `POST /api/v1/auth/login` accepts `identifier` (email or E.164 mobile); `email` remains as a deprecated alias.
- `GET /.well-known/jwks.json` publishes the public keys from `JWT_PUBLIC_KEYS_DIR` for product API token verification; the directory is required outside `DEPLOYMENT_ENVIRONMENT=dev`.
- Initial public MIT release.
