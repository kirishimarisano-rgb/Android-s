# hev-socks5-tunnel Native Prebuilt Artifacts

- Upstream: https://github.com/heiher/hev-socks5-tunnel/releases/tag/2.20.0
- Source archive: `hev-socks5-tunnel.aar` (SHA-256: `ae8a2e96b80b4eccccd037805a4bb4a278090c89dbcae8bc6fcb7634e9a255b9`)
- Extracted files:
  - `libs/hev-tproxy-2.20.0.jar` (`hev.htproxy.TProxyService`)
  - `src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86,x86_64}/libhev-socks5-tunnel.so`

Extracting the official `.aar` into `libs/` and `src/main/jniLibs/` preserves full ABI compatibility and avoids AGP's `minSdkVersion=29` manifest conflict while keeping builds reproducible without requiring an NDK toolchain in CI.
