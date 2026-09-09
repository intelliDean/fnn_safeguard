use anyhow::{bail, Context, Result};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::fs;
use std::path::Path;

#[derive(Clone)]
pub struct IdentityKey {
    pubkey_hex: String,
    raw_len: usize,
}

impl std::fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKey")
            .field("pubkey", &self.pubkey_hex)
            .field("bytes_len", &self.raw_len)
            .finish()
    }
}

impl IdentityKey {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            bail!("Secret key file does not exist at {:?}", path);
        }

        let raw = fs::read(path).with_context(|| format!("Failed to read secret key file {:?}", path))?;

        if raw.len() != 32 {
            bail!(
                "Invalid secret key length in {:?}: expected 32 bytes, got {}",
                path,
                raw.len()
            );
        }

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&raw).context("Invalid secp256k1 secret key bytes in identity file")?;
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let pubkey_bytes = pk.serialize();
        let pubkey_hex = hex::encode(pubkey_bytes);

        Ok(Self {
            pubkey_hex,
            raw_len: raw.len(),
        })
    }

    pub fn public_key_hex(&self) -> &str {
        &self.pubkey_hex
    }

    pub fn matches_public_key(&self, expected_pubkey: &str) -> bool {
        self.pubkey_hex.eq_ignore_ascii_case(expected_pubkey.trim())
    }
}

/// Checks and manages file permissions to prevent the documented FNN 0o400 restore crash.
pub struct PermissionManager;

impl PermissionManager {
    #[cfg(unix)]
    pub fn check_permission_mode(path: impl AsRef<Path>) -> Result<u32> {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(path.as_ref())?;
        Ok(meta.permissions().mode() & 0o777)
    }

    #[cfg(not(unix))]
    pub fn check_permission_mode(_path: impl AsRef<Path>) -> Result<u32> {
        Ok(0o600)
    }

    /// Makes a key file writable prior to restore so std::fs::copy does not fail with EACCES.
    #[cfg(unix)]
    pub fn prepare_for_restore(path: impl AsRef<Path>) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let path = path.as_ref();
        if path.exists() {
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)
                .with_context(|| format!("Failed to set 0o600 write permission on {:?}", path))?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn prepare_for_restore(_path: impl AsRef<Path>) -> Result<()> {
        Ok(())
    }

    /// Hardens the identity key file back to read-only 0o400 after restore.
    #[cfg(unix)]
    pub fn harden_after_restore(path: impl AsRef<Path>) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let path = path.as_ref();
        if path.exists() {
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o400);
            fs::set_permissions(path, perms)
                .with_context(|| format!("Failed to set 0o400 readonly permission on {:?}", path))?;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn harden_after_restore(_path: impl AsRef<Path>) -> Result<()> {
        Ok(())
    }
}
