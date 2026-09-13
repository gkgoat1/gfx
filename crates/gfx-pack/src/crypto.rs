//! Whole-archive age encryption (plan-multistream-pack.md D5).
//!
//! Encryption wraps the complete `.gfxpack` byte stream — never per-entry
//! zip crypto, which would leak entry names and sizes. The cost model is
//! deliberate: decryption materializes the zip before reading (no random
//! access through the cipher), and the plaintext spool lives in a 0700
//! temp dir removed on drop.
//!
//! The heavy lifting is the `age` crate (rage's library); this module is
//! the thin spec/CLI-facing surface: recipient vs. passphrase specs,
//! identity-file parsing, and the `GFX_PACK_PASSPHRASE` convention.

use std::io::Write;

pub use age::secrecy;
pub use age::secrecy::SecretString;
pub use age::x25519;

use crate::PackError;

/// Environment variable consulted for `--encrypt-passphrase` (pack) and for
/// passphrase-encrypted archives (unpack). Never an argv value: argv is
/// world-readable via `ps`.
pub const PASSPHRASE_ENV: &str = "GFX_PACK_PASSPHRASE";

fn crypto_err(e: impl std::fmt::Display) -> PackError {
    PackError::Crypto(e.to_string())
}

/// How to encrypt an archive.
#[derive(Clone, Debug)]
pub enum EncryptSpec {
    /// scrypt passphrase stanza (age's `--passphrase`).
    Passphrase(SecretString),
    /// One or more X25519 recipients (age's `-r age1...`).
    Recipients(Vec<age::x25519::Recipient>),
}

/// Wrap `out` in an age stream writer per `spec`. The caller drives bytes
/// through and calls `.finish()` on the result.
pub fn encrypt_writer<W: Write>(
    out: W,
    spec: &EncryptSpec,
) -> Result<age::stream::StreamWriter<W>, PackError> {
    let encryptor = match spec {
        EncryptSpec::Passphrase(p) => age::Encryptor::with_user_passphrase(p.clone()),
        EncryptSpec::Recipients(rs) => {
            age::Encryptor::with_recipients(rs.iter().map(|r| r as &dyn age::Recipient))
                .map_err(crypto_err)?
        }
    };
    encryptor.wrap_output(out).map_err(PackError::Io)
}

/// Read the passphrase from the environment, when set and non-empty.
pub fn passphrase_from_env() -> Option<SecretString> {
    std::env::var(PASSPHRASE_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .map(SecretString::from)
}

/// Parse an age identity file: one `AGE-SECRET-KEY-...` per line, `#`
/// comments and blank lines ignored (the format `age-keygen` writes).
pub fn parse_identity_file(text: &str) -> Result<Vec<age::x25519::Identity>, PackError> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let id: age::x25519::Identity = line.parse().map_err(|e| {
            crypto_err(format_args!("identity file line {}: {e}", i + 1))
        })?;
        out.push(id);
    }
    if out.is_empty() {
        return Err(crypto_err(format_args!("identity file has no keys")));
    }
    Ok(out)
}

/// Decrypt a complete age file. Passphrase archives need `passphrase`;
/// recipient archives need at least one matching identity. Anything else
/// (wrong key, truncation, tampering) is a hard error — fail closed.
pub fn decrypt_bytes(
    ciphertext: &[u8],
    passphrase: Option<SecretString>,
    identities: &[age::x25519::Identity],
) -> Result<Vec<u8>, PackError> {
    let decryptor = age::Decryptor::new_buffered(ciphertext).map_err(crypto_err)?;
    let mut reader = if decryptor.is_scrypt() {
        let pw = passphrase.ok_or_else(|| {
            PackError::Usage(std::format!(
                "archive is passphrase-encrypted; set {PASSPHRASE_ENV}"
            ))
        })?;
        let id = age::scrypt::Identity::new(pw);
        decryptor
            .decrypt(std::iter::once(&id as &dyn age::Identity))
            .map_err(crypto_err)?
    } else {
        if identities.is_empty() {
            return Err(PackError::Usage(
                "archive is recipient-encrypted; pass --identity <file>".into(),
            ));
        }
        decryptor
            .decrypt(identities.iter().map(|i| i as &dyn age::Identity))
            .map_err(crypto_err)?
    };
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut out).map_err(PackError::Io)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_round_trip_and_wrong_key() {
        let spec = EncryptSpec::Passphrase(SecretString::from("correct horse"));
        let mut w = encrypt_writer(Vec::new(), &spec).unwrap();
        w.write_all(b"multistream payload").unwrap();
        let ciphertext = w.finish().unwrap();
        assert!(ciphertext.starts_with(b"age-encryption.org/v1"));

        let back = decrypt_bytes(
            &ciphertext,
            Some(SecretString::from("correct horse")),
            &[],
        )
        .unwrap();
        assert_eq!(back, b"multistream payload");

        assert!(decrypt_bytes(&ciphertext, Some(SecretString::from("wrong")), &[]).is_err());
        assert!(decrypt_bytes(&ciphertext, None, &[]).is_err(), "missing passphrase fails closed");
        assert!(decrypt_bytes(&ciphertext[..ciphertext.len() / 2], Some(SecretString::from("correct horse")), &[]).is_err());
    }

    #[test]
    fn recipient_round_trip_and_wrong_identity() {
        let id = age::x25519::Identity::generate();
        let spec = EncryptSpec::Recipients(vec![id.to_public()]);
        let mut w = encrypt_writer(Vec::new(), &spec).unwrap();
        w.write_all(b"recipient payload").unwrap();
        let ciphertext = w.finish().unwrap();

        let back = decrypt_bytes(&ciphertext, None, std::slice::from_ref(&id)).unwrap();
        assert_eq!(back, b"recipient payload");

        let other = age::x25519::Identity::generate();
        assert!(decrypt_bytes(&ciphertext, None, &[other]).is_err());
        assert!(decrypt_bytes(&ciphertext, None, &[]).is_err());
    }

    #[test]
    fn identity_files_parse_with_comments() {
        let id = age::x25519::Identity::generate();
        let text = std::format!("# created by a test\n\n{}\n", age::secrecy::ExposeSecret::expose_secret(&id.to_string()));
        let ids = parse_identity_file(&text).unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].to_public().to_string(), id.to_public().to_string());
        assert!(parse_identity_file("# nothing here\n").is_err());
        assert!(parse_identity_file("not-a-key\n").is_err());
    }
}
