use zeroize::{Zeroize, Zeroizing};

#[cfg(not(target_os = "android"))]
const SERVICE: &str = "skyport";
#[cfg(any(target_os = "android", test))]
const MAX_SECRET_BYTES: u64 = 16 * 1024;

#[cfg(not(target_os = "android"))]
pub(crate) fn read(account: &str) -> Result<Option<Zeroizing<String>>, Box<dyn std::error::Error>> {
    let entry = keyring::Entry::new(SERVICE, account)?;
    match entry.get_password() {
        Ok(secret) => Ok(Some(Zeroizing::new(secret))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(keyring::Error::BadEncoding(mut bytes)) => {
            bytes.zeroize();
            Err("Stored credential is not valid UTF-8".into())
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(target_os = "android"))]
pub(crate) fn write(account: &str, secret: &str) -> Result<(), Box<dyn std::error::Error>> {
    keyring::Entry::new(SERVICE, account)?
        .set_password(secret)
        .map_err(Into::into)
}

#[cfg(not(target_os = "android"))]
pub(crate) fn delete(account: &str) -> Result<(), Box<dyn std::error::Error>> {
    let entry = keyring::Entry::new(SERVICE, account)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "android")]
pub(crate) fn read(account: &str) -> Result<Option<Zeroizing<String>>, Box<dyn std::error::Error>> {
    read_file_secret(&credentials_dir()?, account)
}

#[cfg(target_os = "android")]
pub(crate) fn write(account: &str, secret: &str) -> Result<(), Box<dyn std::error::Error>> {
    write_file_secret(&credentials_dir()?, account, secret)
}

#[cfg(target_os = "android")]
pub(crate) fn delete(account: &str) -> Result<(), Box<dyn std::error::Error>> {
    delete_file_secret(&credentials_dir()?, account)
}

#[cfg(target_os = "android")]
fn credentials_dir() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let directory = crate::config::config_dir().join("credentials");
    crate::vault::ensure_secure_directory(&directory)?;
    Ok(directory)
}

#[cfg(any(target_os = "android", test))]
fn credential_path(
    directory: &std::path::Path,
    account: &str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    if account.is_empty()
        || !account
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err("Invalid credential account name".into());
    }
    Ok(directory.join(account))
}

#[cfg(any(target_os = "android", test))]
fn read_file_secret(
    directory: &std::path::Path,
    account: &str,
) -> Result<Option<Zeroizing<String>>, Box<dyn std::error::Error>> {
    use std::io::Read;

    crate::vault::ensure_secure_directory(directory)?;
    let path = credential_path(directory, account)?;
    crate::vault::reject_symlink(&path)?;
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    verify_open_file(&path, &file)?;
    set_restrictive_permissions(&file)?;

    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_SECRET_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SECRET_BYTES {
        return Err("Stored credential is unexpectedly large".into());
    }
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(secret) => Ok(Some(Zeroizing::new(secret))),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Err("Stored credential is not valid UTF-8".into())
        }
    }
}

#[cfg(any(target_os = "android", test))]
fn write_file_secret(
    directory: &std::path::Path,
    account: &str,
    secret: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if secret.len() as u64 > MAX_SECRET_BYTES {
        return Err("Credential is unexpectedly large".into());
    }
    crate::vault::ensure_secure_directory(directory)?;
    let path = credential_path(directory, account)?;
    crate::vault::atomic_write(&path, secret.as_bytes())?;
    Ok(())
}

#[cfg(any(target_os = "android", test))]
fn delete_file_secret(
    directory: &std::path::Path,
    account: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::vault::ensure_secure_directory(directory)?;
    let path = credential_path(directory, account)?;
    crate::vault::reject_symlink(&path)?;
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(any(target_os = "android", test))]
fn verify_open_file(path: &std::path::Path, file: &std::fs::File) -> std::io::Result<()> {
    let path_metadata = std::fs::symlink_metadata(path)?;
    let file_metadata = file.metadata()?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || !file_metadata.is_file()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Credential path is not a regular non-symlink file: {}",
                path.display()
            ),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Credential path changed while it was being opened: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(any(target_os = "android", test))]
fn set_restrictive_permissions(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_round_trips_and_deletes_secrets() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("credentials");

        assert!(read_file_secret(&directory, "admin_token")
            .unwrap()
            .is_none());
        write_file_secret(&directory, "admin_token", "high entropy secret").unwrap();
        assert_eq!(
            read_file_secret(&directory, "admin_token")
                .unwrap()
                .unwrap()
                .as_str(),
            "high entropy secret"
        );
        delete_file_secret(&directory, "admin_token").unwrap();
        assert!(read_file_secret(&directory, "admin_token")
            .unwrap()
            .is_none());
    }

    #[test]
    fn file_store_rejects_unsafe_account_names_and_oversized_secrets() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("credentials");

        assert!(write_file_secret(&directory, "../escape", "secret").is_err());
        let oversized = "x".repeat(MAX_SECRET_BYTES as usize + 1);
        assert!(write_file_secret(&directory, "admin_token", &oversized).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn file_store_forces_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("credentials");
        write_file_secret(&directory, "master_key", "secret").unwrap();

        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(directory.join("master_key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
