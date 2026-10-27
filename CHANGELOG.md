# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `POST /api/v1/auth/login` accepts `identifier` (email or E.164 mobile); `email` remains as a deprecated alias.
- `GET /.well-known/jwks.json` publishes the public keys from `JWT_PUBLIC_KEYS_DIR` for product API token verification; the directory is required outside `DEPLOYMENT_ENVIRONMENT=dev`.
- Initial public MIT release.
