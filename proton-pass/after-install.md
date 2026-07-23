# Proton Pass runtime source installed

1. Install Proton Pass CLI 2.1.0 or newer. On Windows, or outside the documented
   fixed POSIX locations, configure an absolute `secrets.proton_pass.binary_path`.
2. Create a **plain**, narrowly scoped read-only PAT for one runtime vault.
   Agent PATs are intentionally unsupported.
3. Configure `secrets.proton_pass.enabled: true` and set
   `secrets.proton_pass.vault` in the active profile's `config.yaml`.
4. Save the PAT as `PROTON_PASS_PERSONAL_ACCESS_TOKEN` in the active profile's
   Hermes `.env` if it was not entered during installation.
5. Restart Hermes. Vault values do not override existing environment values by
   default. See the plugin README for mapping, reserved names, cache cleanup,
   and platform limitations. Command timeouts must not exceed 300 seconds;
   plaintext cache TTL is disabled by default and must not exceed 30 days.
