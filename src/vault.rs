use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_AAD: &[u8] = b"skyport/vault/envelope/v1";
const LEGACY_AAD: &[u8] = b"";
const AES_GCM_NONCE_LEN: usize = 12;
const CURRENT_KEYRING_ACCOUNT: &str = "master_key";
const PREVIOUS_KEYRING_ACCOUNT: &str = "master_key_previous";
type EnvelopeFingerprint = [u8; 32];

/// A single API key entry stored in the vault.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct VaultEntry {
    pub key_alias: String,
    pub provider: String,
    pub api_key: String,
    pub priority: u32,
    pub enabled: bool,
    pub cooldown_until: Option<DateTime<Utc>>,
    /// OAuth subscription credential: refresh token alongside the short-lived
    /// access token stored in `api_key`.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// When the access token expires (None = never / manual).
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// Which subscription flow produced this entry ("chatgpt", "claude",
    /// "grok", ...). None = plain API key.
    #[serde(default)]
    pub oauth_provider: Option<String>,
    /// Provider-specific request metadata (account id, identity headers).
    #[serde(default)]
    pub oauth_extra: Option<serde_json::Value>,
}

impl fmt::Debug for VaultEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultEntry")
            .field("key_alias", &self.key_alias)
            .field("provider", &self.provider)
            .field("api_key", &"[REDACTED]")
            .field("priority", &self.priority)
            .field("enabled", &self.enabled)
            .field("cooldown_until", &self.cooldown_until)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at", &self.expires_at)
            .field("oauth_provider", &self.oauth_provider)
            .field(
                "oauth_extra",
                &self.oauth_extra.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

// A type with Drop cannot be built with `VaultEntry { ..Default::default() }`.
// Keep that established unit-test construction pattern while ensuring runtime
// entries zeroize their secrets when dropped.
#[cfg(not(test))]
impl Drop for VaultEntry {
    fn drop(&mut self) {
        self.api_key.zeroize();
        self.refresh_token.zeroize();
        if let Some(value) = &mut self.oauth_extra {
            zeroize_json_value(value);
        }
    }
}

/// Summary view of a vault entry with the API key masked.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultEntrySummary {
    pub key_alias: String,
    pub provider: String,
    pub masked_key: String,
    pub priority: u32,
    pub enabled: bool,
    pub cooldown_until: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub oauth_provider: Option<String>,
}

pub struct OAuthCredential<'a> {
    pub provider: &'a str,
    pub alias: &'a str,
    pub access_token: &'a str,
    pub refresh_token: Option<&'a str>,
    pub expires_at: Option<DateTime<Utc>>,
    pub oauth_provider: &'a str,
    pub extra: Option<serde_json::Value>,
}

/// On-disk representation: version + nonce + ciphertext.
#[derive(Serialize, Deserialize)]
struct EncryptedVault {
    /// Missing means the legacy envelope, which did not authenticate AAD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<u8>,
    nonce: String,
    ciphertext: String,
}

struct LoadedEncryptedVault {
    encrypted: EncryptedVault,
    fingerprint: EnvelopeFingerprint,
}

/// In-memory vault holding decrypted entries and the master key.
pub struct Vault {
    pub entries: Vec<VaultEntry>,
    pub(crate) master_key: Vec<u8>,
    #[cfg(not(test))]
    envelope_fingerprint: std::sync::Mutex<EnvelopeFingerprint>,
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn vault_path() -> PathBuf {
    dirs::home_dir()
        .expect("Could not determine home directory")
        .join(".skyport")
        .join("vault.json")
}

fn lock_path(vault_path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let parent = vault_path
        .parent()
        .ok_or("Vault path has no parent directory")?;
    Ok(parent.join("vault.lock"))
}

struct VaultLock {
    _file: File,
}

impl VaultLock {
    fn acquire(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        reject_symlink(path)?;

        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let file = options.open(path)?;
        verify_open_file(path, &file)?;
        set_restrictive_file_permissions(&file)?;
        file.lock()?;
        Ok(Self { _file: file })
    }
}

pub(crate) fn ensure_secure_directory(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => verify_directory(path, &metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Err(error) = create_secure_directory(path) {
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error);
                }
            }
            let metadata = std::fs::symlink_metadata(path)?;
            verify_directory(path, &metadata)?;
        }
        Err(error) => return Err(error),
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_secure_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)
}

#[cfg(not(unix))]
fn create_secure_directory(path: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new().create(path)
}

fn verify_directory(path: &Path, metadata: &std::fs::Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Refusing to use symlinked vault directory: {}",
                path.display()
            ),
        ));
    }
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Vault directory path is not a directory: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

pub(crate) fn reject_symlink(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Refusing to use symlinked vault path: {}", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn secure_file_exists(path: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Refusing to use symlinked vault path: {}", path.display()),
                ));
            }
            if !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Vault path is not a regular file: {}", path.display()),
                ));
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn verify_open_file(path: &Path, file: &File) -> io::Result<()> {
    let path_metadata = std::fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Vault path is not a regular non-symlink file: {}",
                path.display()
            ),
        ));
    }

    let file_metadata = file.metadata()?;
    if !file_metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Opened vault path is not a regular file: {}",
                path.display()
            ),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Vault path changed while it was being opened: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn set_restrictive_file_permissions(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

// ---------------------------------------------------------------------------
// Master-key helpers
// ---------------------------------------------------------------------------

enum StoredKey {
    Missing,
    Invalid,
    Present(Zeroizing<Vec<u8>>),
}

impl StoredKey {
    fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Present(key) => Some(key.as_slice()),
            Self::Missing | Self::Invalid => None,
        }
    }
}

fn read_stored_key(account: &str) -> Result<StoredKey, Box<dyn std::error::Error>> {
    let Some(password) = crate::credential_store::read(account)
        .map_err(|_| "Failed to access vault credential store")?
    else {
        return Ok(StoredKey::Missing);
    };
    let mut key = Zeroizing::new(Vec::with_capacity(32));
    if BASE64.decode_vec(password.as_bytes(), &mut key).is_err() || key.len() != 32 {
        return Ok(StoredKey::Invalid);
    }
    Ok(StoredKey::Present(key))
}

fn set_stored_key(account: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let encoded = Zeroizing::new(BASE64.encode(key));
    crate::credential_store::write(account, encoded.as_str())
        .map_err(|_| "Failed to access vault credential store".into())
}

fn delete_stored_key(account: &str) -> Result<(), Box<dyn std::error::Error>> {
    crate::credential_store::delete(account)
        .map_err(|_| "Failed to access vault credential store".into())
}

fn generate_master_key() -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(vec![0_u8; 32]);
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut key);
    key
}

fn get_or_create_master_key() -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    match read_stored_key(CURRENT_KEYRING_ACCOUNT)? {
        StoredKey::Present(key) => Ok(key),
        StoredKey::Missing => {
            let key = generate_master_key();
            set_stored_key(CURRENT_KEYRING_ACCOUNT, &key)?;
            Ok(key)
        }
        StoredKey::Invalid => Err("Master key in credential store is invalid".into()),
    }
}

// ---------------------------------------------------------------------------
// AES-256-GCM helpers
// ---------------------------------------------------------------------------

fn encrypt(
    data: &[u8],
    key: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Invalid AES-256 key length")?;

    let mut nonce_bytes = [0u8; AES_GCM_NONCE_LEN];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: data, aad })
        .map_err(|e| format!("Encryption failed: {e}"))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

fn decrypt(
    nonce: &[u8],
    ciphertext: &[u8],
    key: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    if nonce.len() != AES_GCM_NONCE_LEN {
        return Err(format!(
            "Invalid AES-GCM nonce length: expected {AES_GCM_NONCE_LEN}, got {}",
            nonce.len()
        )
        .into());
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Invalid AES-256 key length")?;
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| format!("Decryption failed: {e}"))?;
    Ok(Zeroizing::new(plaintext))
}

fn encrypt_entries(
    entries: &[VaultEntry],
    key: &[u8],
) -> Result<EncryptedVault, Box<dyn std::error::Error>> {
    let plaintext = Zeroizing::new(serde_json::to_vec(entries)?);
    let (nonce, ciphertext) = encrypt(&plaintext, key, ENVELOPE_AAD)?;
    Ok(EncryptedVault {
        version: Some(ENVELOPE_VERSION),
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
    })
}

fn decrypt_entries(
    encrypted: &EncryptedVault,
    key: &[u8],
) -> Result<Vec<VaultEntry>, Box<dyn std::error::Error>> {
    let aad = match encrypted.version {
        Some(ENVELOPE_VERSION) => ENVELOPE_AAD,
        None => LEGACY_AAD,
        Some(version) => {
            return Err(format!("Unsupported vault envelope version: {version}").into())
        }
    };
    let nonce = BASE64.decode(&encrypted.nonce)?;
    let ciphertext = BASE64.decode(&encrypted.ciphertext)?;
    let plaintext = decrypt(&nonce, &ciphertext, key, aad)?;
    Ok(serde_json::from_slice(&plaintext)?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeySelection {
    Current,
    Previous,
}

#[derive(Debug)]
struct EnvelopeDecryptionFailed;

fn decrypt_with_key_selection(
    encrypted: &EncryptedVault,
    current_key: Option<&[u8]>,
    previous_key: Option<&[u8]>,
) -> Result<(Vec<VaultEntry>, KeySelection), EnvelopeDecryptionFailed> {
    if let Some(key) = current_key {
        if let Ok(entries) = decrypt_entries(encrypted, key) {
            return Ok((entries, KeySelection::Current));
        }
    }
    if let Some(key) = previous_key {
        if let Ok(entries) = decrypt_entries(encrypted, key) {
            return Ok((entries, KeySelection::Previous));
        }
    }
    Err(EnvelopeDecryptionFailed)
}

type LoadedVault = (Vec<VaultEntry>, Zeroizing<Vec<u8>>);

fn decrypt_existing_vault(
    encrypted: &EncryptedVault,
) -> Result<LoadedVault, Box<dyn std::error::Error>> {
    let current = read_stored_key(CURRENT_KEYRING_ACCOUNT)?;
    if let Some(current_key) = current.as_bytes() {
        if let Ok(entries) = decrypt_entries(encrypted, current_key) {
            delete_stored_key(PREVIOUS_KEYRING_ACCOUNT)?;
            return Ok((entries, Zeroizing::new(current_key.to_vec())));
        }
    }

    let previous = read_stored_key(PREVIOUS_KEYRING_ACCOUNT)?;
    let (entries, selection) = decrypt_with_key_selection(encrypted, None, previous.as_bytes())
        .map_err(|_| -> Box<dyn std::error::Error> {
            "Vault could not be decrypted or recovered".into()
        })?;
    debug_assert_eq!(selection, KeySelection::Previous);

    let recovered_key = previous
        .as_bytes()
        .ok_or("Vault could not be decrypted or recovered")?;
    // Restoring current before deleting previous keeps at least one usable
    // key through every interruption point.
    set_stored_key(CURRENT_KEYRING_ACCOUNT, recovered_key)?;
    delete_stored_key(PREVIOUS_KEYRING_ACCOUNT)?;
    Ok((entries, Zeroizing::new(recovered_key.to_vec())))
}

fn envelope_fingerprint(bytes: &[u8]) -> EnvelopeFingerprint {
    Sha256::digest(bytes).into()
}

fn fingerprints_match(expected: &EnvelopeFingerprint, actual: &EnvelopeFingerprint) -> bool {
    expected == actual
}

fn post_load_fingerprint(
    loaded: EnvelopeFingerprint,
    migrated: Option<EnvelopeFingerprint>,
) -> EnvelopeFingerprint {
    migrated.unwrap_or(loaded)
}

fn serialize_encrypted_vault(
    encrypted: &EncryptedVault,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(serde_json::to_vec_pretty(encrypted)?)
}

fn read_encrypted_vault(path: &Path) -> Result<LoadedEncryptedVault, Box<dyn std::error::Error>> {
    reject_symlink(path)?;
    let mut file = OpenOptions::new().read(true).open(path)?;
    verify_open_file(path, &file)?;
    set_restrictive_file_permissions(&file)?;

    let mut raw = Vec::new();
    file.read_to_end(&mut raw)?;
    Ok(LoadedEncryptedVault {
        encrypted: serde_json::from_slice(&raw)?,
        fingerprint: envelope_fingerprint(&raw),
    })
}

fn persist_entries(
    path: &Path,
    entries: &[VaultEntry],
    key: &[u8],
) -> Result<EnvelopeFingerprint, Box<dyn std::error::Error>> {
    let encrypted = encrypt_entries(entries, key)?;
    let json = serialize_encrypted_vault(&encrypted)?;
    let fingerprint = envelope_fingerprint(&json);
    atomic_write(path, &json)?;
    Ok(fingerprint)
}

struct PendingTempFile(Option<PathBuf>);

impl Drop for PendingTempFile {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub(crate) fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Vault path has no parent"))?;
    reject_symlink(path)?;

    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "Vault path has no file name")
    })?;
    let (temporary_path, mut temporary_file) = create_temporary_file(parent, file_name)?;
    let mut pending = PendingTempFile(Some(temporary_path.clone()));

    temporary_file.write_all(contents)?;
    temporary_file.sync_all()?;
    drop(temporary_file);

    // Recheck immediately before replacement. Rename replaces a Unix symlink
    // itself rather than following it; Windows receives the same best-effort check.
    reject_symlink(path)?;
    let _ = secure_file_exists(path)?;
    atomic_replace(&temporary_path, path)?;
    pending.0 = None;

    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn create_temporary_file(
    parent: &Path,
    file_name: &std::ffi::OsStr,
) -> io::Result<(PathBuf, File)> {
    for _ in 0..128 {
        let random = rand::random::<u64>();
        let name = format!(
            ".{}.{}.{}.tmp",
            file_name.to_string_lossy(),
            std::process::id(),
            random
        );
        let path = parent.join(name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(&path) {
            Ok(file) => {
                set_restrictive_file_permissions(&file)?;
                return Ok((path, file));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "Could not create a unique vault temporary file",
    ))
}

#[cfg(unix)]
pub(crate) fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
pub(crate) fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    const ERROR_FILE_NOT_FOUND: i32 = 2;

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn ReplaceFileW(
            replaced_file_name: *const u16,
            replacement_file_name: *const u16,
            backup_file_name: *const u16,
            replace_flags: u32,
            exclude: *mut std::ffi::c_void,
            reserved: *mut std::ffi::c_void,
        ) -> i32;
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();

    // SAFETY: Both paths are NUL-terminated for the duration of each call and
    // the optional pointers are null as required by these Win32 APIs.
    if unsafe {
        ReplaceFileW(
            destination.as_ptr(),
            source.as_ptr(),
            null(),
            0,
            null_mut(),
            null_mut(),
        )
    } != 0
    {
        return Ok(());
    }

    let replace_error = io::Error::last_os_error();
    if replace_error.raw_os_error() != Some(ERROR_FILE_NOT_FOUND) {
        return Err(replace_error);
    }

    // ReplaceFileW requires an existing destination. MoveFileExW provides the
    // atomic same-volume rename used for a new vault (and handles a creation race).
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    std::fs::rename(source, destination)
}

// ---------------------------------------------------------------------------
// Vault implementation
// ---------------------------------------------------------------------------

impl Vault {
    /// Load the vault from disk (decrypting it) or create an empty one.
    pub fn load_or_create() -> Result<Self, Box<dyn std::error::Error>> {
        let path = vault_path();
        let parent = path.parent().ok_or("Vault path has no parent directory")?;
        ensure_secure_directory(parent)?;
        let _lock = VaultLock::acquire(&lock_path(&path)?)?;

        let vault_exists = secure_file_exists(&path)?;
        let (entries, master_key, fingerprint) = if vault_exists {
            let loaded = read_encrypted_vault(&path)?;
            let legacy = loaded.encrypted.version.is_none();
            let (entries, master_key) = decrypt_existing_vault(&loaded.encrypted)?;
            let migrated = if legacy {
                Some(persist_entries(&path, &entries, &master_key)?)
            } else {
                None
            };
            (
                entries,
                master_key,
                post_load_fingerprint(loaded.fingerprint, migrated),
            )
        } else {
            let master_key = get_or_create_master_key()?;
            let entries = Vec::new();
            let fingerprint = persist_entries(&path, &entries, &master_key)?;
            delete_stored_key(PREVIOUS_KEYRING_ACCOUNT)?;
            (entries, master_key, fingerprint)
        };

        #[cfg(test)]
        let _ = fingerprint;
        Ok(Self {
            entries,
            master_key: master_key.to_vec(),
            #[cfg(not(test))]
            envelope_fingerprint: std::sync::Mutex::new(fingerprint),
        })
    }

    /// Generate a new master key and re-encrypt the vault without leaving a
    /// crash window where the on-disk vault has no usable key.
    pub fn rotate_master_key(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let path = vault_path();
        let parent = path.parent().ok_or("Vault path has no parent directory")?;
        ensure_secure_directory(parent)?;
        let _lock = VaultLock::acquire(&lock_path(&path)?)?;

        if !secure_file_exists(&path)? {
            return Err("Vault file is missing; refusing master-key rotation".into());
        }
        let loaded = read_encrypted_vault(&path)?;
        #[cfg(not(test))]
        {
            let expected = *self
                .envelope_fingerprint
                .get_mut()
                .map_err(|_| "Vault fingerprint lock poisoned")?;
            if !fingerprints_match(&expected, &loaded.fingerprint) {
                return Err("Vault changed; reload before rotating it".into());
            }
        }
        let (_disk_entries, active_key) = decrypt_existing_vault(&loaded.encrypted)?;
        if active_key.as_slice() != self.master_key.as_slice() {
            return Err("Vault key changed; reload before rotating it".into());
        }

        let new_key = generate_master_key();
        let replacement = encrypt_entries(&self.entries, &new_key)?;
        let replacement_json = serialize_encrypted_vault(&replacement)?;
        let replacement_fingerprint = envelope_fingerprint(&replacement_json);

        // The previous key must be durable before current is changed. From
        // here until cleanup, either current or previous decrypts either file.
        set_stored_key(PREVIOUS_KEYRING_ACCOUNT, &active_key)?;
        set_stored_key(CURRENT_KEYRING_ACCOUNT, &new_key)?;
        if atomic_write(&path, &replacement_json).is_err() {
            return Err(
                "Master-key rotation did not complete; recovery will run on next load".into(),
            );
        }

        self.master_key.zeroize();
        self.master_key.extend_from_slice(&new_key);
        #[cfg(not(test))]
        {
            *self
                .envelope_fingerprint
                .get_mut()
                .map_err(|_| "Vault fingerprint lock poisoned")? = replacement_fingerprint;
        }
        #[cfg(test)]
        let _ = replacement_fingerprint;
        delete_stored_key(PREVIOUS_KEYRING_ACCOUNT)?;
        Ok(())
    }

    /// Encrypt and persist the vault to disk.
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Unit tests exercise routing with synthetic keys; never write those to a user's vault.
        #[cfg(test)]
        {
            Ok(())
        }

        #[cfg(not(test))]
        {
            let mut expected = self
                .envelope_fingerprint
                .lock()
                .map_err(|_| "Vault fingerprint lock poisoned")?;
            let path = vault_path();
            let parent = path.parent().ok_or("Vault path has no parent directory")?;
            ensure_secure_directory(parent)?;
            let _lock = VaultLock::acquire(&lock_path(&path)?)?;
            if !secure_file_exists(&path)? {
                return Err("Vault file is missing; refusing to overwrite it".into());
            }
            let loaded = read_encrypted_vault(&path)?;
            if !fingerprints_match(&expected, &loaded.fingerprint) {
                return Err("Vault changed; reload before saving".into());
            }
            let (_disk_entries, active_key) = decrypt_existing_vault(&loaded.encrypted)?;
            if active_key.as_slice() != self.master_key.as_slice() {
                return Err("Vault key changed; reload before saving".into());
            }
            let persisted = persist_entries(&path, &self.entries, &self.master_key)?;
            *expected = persisted;
            Ok(())
        }
    }

    /// Add a new API key to the vault. Aliases must be unique: a duplicate
    /// alias would make enable/disable/cooldown target only the first match
    /// and break the router's failover bookkeeping.
    pub fn add_key(
        &mut self,
        provider: &str,
        alias: &str,
        api_key: &str,
        priority: u32,
    ) -> Result<(), String> {
        let alias = alias.trim();
        if alias.is_empty() {
            return Err("Key alias cannot be empty".to_string());
        }
        if self.entries.iter().any(|e| e.key_alias == alias) {
            return Err(format!("A key with alias \"{alias}\" already exists"));
        }
        self.entries.push(VaultEntry {
            key_alias: alias.to_string(),
            provider: provider.to_string(),
            api_key: api_key.to_string(),
            priority,
            enabled: true,
            cooldown_until: None,
            refresh_token: None,
            expires_at: None,
            oauth_provider: None,
            oauth_extra: None,
        });
        Ok(())
    }

    /// Replace a plain API key in place without changing its routing metadata.
    /// Returns false when the alias is absent or belongs to an OAuth entry.
    pub fn replace_key(&mut self, alias: &str, api_key: &str) -> bool {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.key_alias == alias && entry.oauth_provider.is_none())
        else {
            return false;
        };

        entry.api_key.zeroize();
        entry.api_key.push_str(api_key);
        entry.enabled = true;
        entry.cooldown_until = None;
        true
    }

    /// Add or replace an OAuth subscription credential. Unlike `add_key` the
    /// alias may already exist: re-linking an account refreshes the stored
    /// tokens in place instead of failing. Returns true when an existing entry
    /// was replaced and false when a new one was inserted.
    pub fn upsert_oauth_key(&mut self, credential: OAuthCredential<'_>) -> bool {
        let OAuthCredential {
            provider,
            alias,
            access_token,
            refresh_token,
            expires_at,
            oauth_provider,
            extra,
        } = credential;
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.key_alias == alias && e.provider == provider)
        {
            entry.api_key.zeroize();
            entry.api_key.push_str(access_token);
            entry.refresh_token.zeroize();
            entry.refresh_token = refresh_token.map(str::to_string);
            entry.expires_at = expires_at;
            entry.oauth_provider = Some(oauth_provider.to_string());
            if let Some(value) = &mut entry.oauth_extra {
                zeroize_json_value(value);
            }
            entry.oauth_extra = extra;
            entry.enabled = true;
            entry.cooldown_until = None;
            return true;
        }
        self.entries.push(VaultEntry {
            key_alias: alias.to_string(),
            provider: provider.to_string(),
            api_key: access_token.to_string(),
            priority: 0,
            enabled: true,
            cooldown_until: None,
            refresh_token: refresh_token.map(str::to_string),
            expires_at,
            oauth_provider: Some(oauth_provider.to_string()),
            oauth_extra: extra,
        });
        false
    }

    /// Remove a key by alias, returning whether an entry existed.
    pub fn remove_key(&mut self, alias: &str) -> bool {
        let previous_len = self.entries.len();
        self.entries.retain(|e| e.key_alias != alias);
        self.entries.len() != previous_len
    }

    /// Disable a key by alias, returning whether an entry existed.
    pub fn disable_key(&mut self, alias: &str) -> bool {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.key_alias == alias) {
            entry.enabled = false;
            true
        } else {
            false
        }
    }

    /// Enable a key by alias, returning whether an entry existed.
    pub fn enable_key(&mut self, alias: &str) -> bool {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.key_alias == alias) {
            entry.enabled = true;
            true
        } else {
            false
        }
    }

    /// List all keys with masked API key values.
    pub fn list_keys(&self) -> Vec<VaultEntrySummary> {
        self.entries
            .iter()
            .map(|e| VaultEntrySummary {
                key_alias: e.key_alias.clone(),
                provider: e.provider.clone(),
                masked_key: mask_key(&e.api_key),
                priority: e.priority,
                enabled: e.enabled,
                cooldown_until: e.cooldown_until,
                expires_at: e.expires_at,
                oauth_provider: e.oauth_provider.clone(),
            })
            .collect()
    }

    /// The active OAuth subscription entry for a provider config id, if any.
    pub fn oauth_entry(&self, provider: &str) -> Option<&VaultEntry> {
        self.entries
            .iter()
            .find(|e| e.provider == provider && e.oauth_provider.is_some())
    }

    /// Get keys for a specific provider, sorted by priority (ascending).
    pub fn get_keys_for_provider(&self, provider: &str) -> Vec<&VaultEntry> {
        let mut keys: Vec<&VaultEntry> = self
            .entries
            .iter()
            .filter(|e| e.provider == provider)
            .collect();
        keys.sort_by_key(|e| e.priority);
        keys
    }

    /// Local OpenAI-compatible servers do not require a secret in the vault.
    pub fn is_keyless_provider(provider: &str) -> bool {
        matches!(provider, "ollama" | "lmstudio")
    }

    /// Set a cooldown timestamp, returning whether an entry existed.
    pub fn set_cooldown(&mut self, alias: &str, until: DateTime<Utc>) -> bool {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.key_alias == alias) {
            entry.cooldown_until = Some(until);
            true
        } else {
            false
        }
    }
}

fn zeroize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(value) => value.zeroize(),
        serde_json::Value::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                zeroize_json_value(value);
            }
        }
        _ => {}
    }
}

/// Mask an API key, showing no prefix and at most the last four Unicode characters.
fn mask_key(key: &str) -> String {
    let mut suffix: Vec<char> = key.chars().rev().take(4).collect();
    if suffix.len() < 4 || key.chars().count() <= 4 {
        return "****".to_string();
    }
    suffix.reverse();
    format!("****{}", suffix.into_iter().collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::{
        decrypt, decrypt_entries, decrypt_with_key_selection, encrypt, encrypt_entries,
        envelope_fingerprint, fingerprints_match, mask_key, post_load_fingerprint, EncryptedVault,
        KeySelection, OAuthCredential, Vault, VaultEntry, ENVELOPE_AAD, LEGACY_AAD,
    };
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use chrono::Utc;
    use zeroize::Zeroizing;

    #[test]
    fn encryption_round_trip_and_tamper_detection() {
        let key = [7_u8; 32];
        let (nonce, mut ciphertext) = encrypt(b"skyport secret", &key, ENVELOPE_AAD).unwrap();
        assert_eq!(
            decrypt(&nonce, &ciphertext, &key, ENVELOPE_AAD)
                .unwrap()
                .as_slice(),
            b"skyport secret"
        );
        ciphertext[0] ^= 1;
        assert!(decrypt(&nonce, &ciphertext, &key, ENVELOPE_AAD).is_err());
    }

    #[test]
    fn malformed_nonce_lengths_are_rejected() {
        let key = [3_u8; 32];
        for length in [0, 1, 11, 13, 64] {
            assert!(decrypt(&vec![0; length], b"ciphertext", &key, ENVELOPE_AAD).is_err());
        }
    }

    #[test]
    fn aad_and_version_tampering_are_rejected() {
        let key = [9_u8; 32];
        let (nonce, ciphertext) = encrypt(b"secret", &key, ENVELOPE_AAD).unwrap();
        assert!(decrypt(&nonce, &ciphertext, &key, b"skyport/vault/envelope/v2").is_err());

        let mut envelope = encrypt_entries(&[], &key).unwrap();
        envelope.version = None;
        assert!(decrypt_entries(&envelope, &key).is_err());
    }

    #[test]
    fn exact_envelope_fingerprints_detect_stale_writers_and_migration() {
        let loaded_bytes = br#"{"nonce":"abc","ciphertext":"def"}"#;
        let reformatted_bytes = br#"{ "nonce": "abc", "ciphertext": "def" }"#;
        let loaded = envelope_fingerprint(loaded_bytes);
        let reformatted = envelope_fingerprint(reformatted_bytes);

        assert!(fingerprints_match(
            &loaded,
            &envelope_fingerprint(loaded_bytes)
        ));
        assert!(!fingerprints_match(&loaded, &reformatted));
        assert_eq!(post_load_fingerprint(loaded, None), loaded);
        assert_eq!(
            post_load_fingerprint(loaded, Some(reformatted)),
            reformatted
        );
    }

    #[test]
    fn key_selection_recovers_both_rotation_crash_windows() {
        let old_key = [4_u8; 32];
        let new_key = [8_u8; 32];
        let wrong_key = [12_u8; 32];
        let entries = vec![VaultEntry {
            key_alias: "rotation".to_string(),
            provider: "example".to_string(),
            api_key: "rotation-secret".to_string(),
            ..Default::default()
        }];
        let old_envelope = encrypt_entries(&entries, &old_key).unwrap();
        let new_envelope = encrypt_entries(&entries, &new_key).unwrap();

        // Current was replaced, but the old vault file is still present.
        let (recovered, selected) =
            decrypt_with_key_selection(&old_envelope, Some(&new_key), Some(&old_key)).unwrap();
        assert_eq!(selected, KeySelection::Previous);
        assert_eq!(recovered[0].api_key, "rotation-secret");

        // The vault replacement completed, but previous-key cleanup did not.
        let (_, selected) =
            decrypt_with_key_selection(&new_envelope, Some(&new_key), Some(&old_key)).unwrap();
        assert_eq!(selected, KeySelection::Current);

        // A missing current entry can still be restored from the staged key.
        let (_, selected) =
            decrypt_with_key_selection(&old_envelope, None, Some(&old_key)).unwrap();
        assert_eq!(selected, KeySelection::Previous);
        assert!(
            decrypt_with_key_selection(&old_envelope, Some(&wrong_key), Some(&new_key)).is_err()
        );
    }

    #[test]
    fn legacy_unversioned_envelope_remains_readable() {
        let key = [5_u8; 32];
        let entries = vec![VaultEntry {
            key_alias: "legacy".to_string(),
            provider: "example".to_string(),
            api_key: "legacy-secret".to_string(),
            enabled: true,
            ..Default::default()
        }];
        let plaintext = Zeroizing::new(serde_json::to_vec(&entries).unwrap());
        let (nonce, ciphertext) = encrypt(&plaintext, &key, LEGACY_AAD).unwrap();
        let envelope = EncryptedVault {
            version: None,
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        };

        let decrypted = decrypt_entries(&envelope, &key).unwrap();
        assert_eq!(decrypted.len(), 1);
        assert_eq!(decrypted[0].api_key, "legacy-secret");
    }

    #[test]
    fn debug_and_masking_do_not_expose_secrets_or_prefixes() {
        let entry = VaultEntry {
            key_alias: "main".to_string(),
            provider: "example".to_string(),
            api_key: "prefix-super-secret".to_string(),
            refresh_token: Some("refresh-super-secret".to_string()),
            oauth_extra: Some(serde_json::json!({"identity": "private-value"})),
            ..Default::default()
        };
        let debug = format!("{entry:?}");
        assert!(!debug.contains("prefix-super-secret"));
        assert!(!debug.contains("refresh-super-secret"));
        assert!(!debug.contains("private-value"));
        assert!(debug.contains("[REDACTED]"));

        assert_eq!(mask_key("prefix-1234"), "****1234");
        assert_eq!(mask_key("prefix-一二三四"), "****一二三四");
        assert_eq!(mask_key("短🔑"), "****");
    }

    #[test]
    fn mutators_report_existence_and_replace_plain_keys_in_place() {
        let mut vault = Vault {
            entries: Vec::new(),
            master_key: vec![0; 32],
        };
        vault.add_key("example", "main", "old-secret", 4).unwrap();

        assert!(vault.replace_key("main", "new-secret"));
        assert_eq!(vault.entries[0].api_key, "new-secret");
        assert_eq!(vault.entries[0].priority, 4);
        assert!(vault.disable_key("main"));
        assert!(!vault.disable_key("missing"));
        assert!(vault.enable_key("main"));
        assert!(vault.remove_key("main"));
        assert!(!vault.remove_key("main"));
    }

    #[test]
    fn upsert_oauth_key_replaces_in_place_and_round_trips() {
        let mut vault = Vault {
            entries: vec![VaultEntry {
                key_alias: "subscription-chatgpt".to_string(),
                provider: "chatgpt".to_string(),
                api_key: "old-token".to_string(),
                priority: 0,
                enabled: true,
                cooldown_until: Some(Utc::now()),
                ..Default::default()
            }],
            master_key: vec![0; 32],
        };
        assert!(vault.upsert_oauth_key(OAuthCredential {
            provider: "chatgpt",
            alias: "subscription-chatgpt",
            access_token: "new-token",
            refresh_token: Some("refresh-token"),
            expires_at: Some(Utc::now()),
            oauth_provider: "chatgpt",
            extra: Some(serde_json::json!({"account": "me@example.com"})),
        }));
        assert_eq!(
            vault.entries.len(),
            1,
            "re-linking must not duplicate entries"
        );
        let entry = &vault.entries[0];
        assert_eq!(entry.api_key, "new-token");
        assert_eq!(entry.refresh_token.as_deref(), Some("refresh-token"));
        assert_eq!(entry.oauth_provider.as_deref(), Some("chatgpt"));
        assert_eq!(
            entry.oauth_extra.as_ref().unwrap()["account"],
            "me@example.com"
        );
        assert!(entry.enabled);
        assert!(
            entry.cooldown_until.is_none(),
            "re-link must clear cooldowns"
        );
        assert!(vault.oauth_entry("chatgpt").is_some());
    }
}
