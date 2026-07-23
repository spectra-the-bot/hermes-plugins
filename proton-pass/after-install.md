# Proton Pass runtime source installed

1. Install Proton Pass CLI 2.1.0 or newer.
2. Create a **plain**, narrowly scoped read-only PAT for one runtime vault.
   Agent PATs are intentionally unsupported.
3. Configure `secrets.proton_pass.enabled: true` and set
   `secrets.proton_pass.vault` in the active profile's `config.yaml`.
4. Save the PAT as `PROTON_PASS_PERSONAL_ACCESS_TOKEN` in the active profile's
   Hermes `.env` if it was not entered during installation.
5. Restart Hermes. See the plugin README for mapping and cache behavior.
