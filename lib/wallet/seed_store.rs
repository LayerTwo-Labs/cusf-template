//! The wallet's seed store: a single JSON file (`seed.json`).
//!

use std::path::{Path, PathBuf};

use bdk_wallet::bip39::{Language, Mnemonic};
use either::Either;
use rand::Rng as _;
use serde::{Deserialize, Serialize};

use crate::wallet::{
    error,
    mnemonic::{EncryptedMnemonic, KdfParams},
};

/// A seed to persist: either plaintext, or encrypted under a password.
pub(in crate::wallet) enum Seed<'a> {
    Plaintext(&'a Mnemonic),
    Encrypted(&'a EncryptedMnemonic),
}

const SEED_FILE_NAME: &str = "seed.json";

const CURRENT_VERSION: u32 = 1;

/// The seed as stored in `seed.json`
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum StoredSeed {
    Plaintext {
        mnemonic: String,
    },
    Encrypted {
        #[serde(with = "hex::serde")]
        initialization_vector: Vec<u8>,
        #[serde(with = "hex::serde")]
        ciphertext_mnemonic: Vec<u8>,
        #[serde(with = "hex::serde")]
        key_salt: Vec<u8>,
        kdf: StoredKdfParams,
    },
}

/// The Argon2id cost a seed was encrypted under, as stored in `seed.json`.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoredKdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl From<KdfParams> for StoredKdfParams {
    fn from(
        KdfParams {
            memory_kib,
            iterations,
            parallelism,
        }: KdfParams,
    ) -> Self {
        Self {
            memory_kib,
            iterations,
            parallelism,
        }
    }
}

impl From<StoredKdfParams> for KdfParams {
    fn from(
        StoredKdfParams {
            memory_kib,
            iterations,
            parallelism,
        }: StoredKdfParams,
    ) -> Self {
        Self {
            memory_kib,
            iterations,
            parallelism,
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SeedFile {
    version: u32,
    /// Informational only.
    created_at: std::time::SystemTime,
    /// The node's tip height when this seed was generated `None` for restored
    /// seeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    birthday_height: Option<u32>,
    seed: StoredSeed,
}

/// The wallet's seed store.
pub(in crate::wallet) struct SeedStore {
    path: PathBuf,
    /// Serializes seed inserts, so two concurrent `CreateWallet` calls cannot
    /// both pass the "does a seed already exist" check. Stores in *other*
    /// processes are held off by the publish in [`write_seed_file`], which
    /// refuses to replace a seed file that is already there.
    insert_lock: tokio::sync::Mutex<()>,
}

impl SeedStore {
    pub(in crate::wallet) fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join(SEED_FILE_NAME),
            insert_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// The stored seed, if the wallet has been created.
    pub(in crate::wallet) async fn read_mnemonic(
        &self,
    ) -> Result<Option<Either<Mnemonic, EncryptedMnemonic>>, error::ReadSeed> {
        let Some(seed_file) = read_seed_file(&self.path)? else {
            return Ok(None);
        };
        let seed = match seed_file.seed {
            StoredSeed::Plaintext { mnemonic } => Either::Left(
                Mnemonic::parse_in_normalized(Language::English, &mnemonic)
                    .map_err(error::ParseMnemonic::from)?,
            ),
            StoredSeed::Encrypted {
                initialization_vector,
                ciphertext_mnemonic,
                key_salt,
                kdf,
            } => Either::Right(EncryptedMnemonic {
                initialization_vector,
                ciphertext_mnemonic,
                key_salt,
                kdf: kdf.into(),
            }),
        };
        Ok(Some(seed))
    }

    /// The wallet's birthday height, if one was recorded at creation.
    pub(in crate::wallet) async fn read_birthday_height(
        &self,
    ) -> Result<Option<u32>, error::ReadSeed> {
        Ok(read_seed_file(&self.path)?.and_then(|seed_file| seed_file.birthday_height))
    }

    /// Persist the seed for a newly created wallet. `birthday_height` must
    /// only be `Some` for freshly GENERATED seeds (see [`SeedFile`]).
    pub(in crate::wallet) async fn insert_seed(
        &self,
        seed: Seed<'_>,
        birthday_height: Option<u32>,
    ) -> Result<(), error::InsertSeed> {
        let _guard = self.insert_lock.lock().await;
        if self.path.exists() {
            return Err(error::InsertSeed::AlreadyExists);
        }
        let seed_file = SeedFile {
            version: CURRENT_VERSION,
            created_at: std::time::SystemTime::now(),
            birthday_height,
            seed: match seed {
                Seed::Plaintext(mnemonic) => StoredSeed::Plaintext {
                    mnemonic: mnemonic.to_string(),
                },
                Seed::Encrypted(encrypted) => StoredSeed::Encrypted {
                    initialization_vector: encrypted.initialization_vector.clone(),
                    ciphertext_mnemonic: encrypted.ciphertext_mnemonic.clone(),
                    key_salt: encrypted.key_salt.clone(),
                    kdf: encrypted.kdf.into(),
                },
            },
        };
        let () = write_seed_file(&self.path, &seed_file).map_err(|err| {
            // Losing the publish race: another process created the wallet
            // between the check above and the write. Report the wallet as
            // already there, which is what the caller now sees on disk.
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                error::InsertSeed::AlreadyExists
            } else {
                error::InsertSeed::Io(err)
            }
        })?;
        Ok(())
    }
}

fn read_seed_file(path: &Path) -> Result<Option<SeedFile>, error::ReadSeed> {
    let contents = match std::fs::read(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(error::ReadSeedInner::Io(err).into()),
    };
    let seed_file: SeedFile =
        serde_json::from_slice(&contents).map_err(error::ReadSeedInner::Json)?;
    Ok(Some(seed_file))
}

/// Write the seed file atomically and durably: temp file (0600) + fsync +
/// hard link + directory fsync, so a crash can never leave a bad seed file.
///
/// Publishing with a link rather than a rename is what makes "there is no
/// seed yet" the kernel's decision: [`std::fs::hard_link`] fails with
/// [`std::io::ErrorKind::AlreadyExists`] if the seed file is already there,
/// where a rename would silently replace a seed another process just wrote.
/// An `AlreadyExists` out of here therefore means exactly that: someone else
/// got their seed in first.
fn write_seed_file(path: &Path, seed_file: &SeedFile) -> Result<(), std::io::Error> {
    let contents = serde_json::to_vec_pretty(seed_file).expect("seed file serialization is total");
    // Unique per write: two processes writing at once must not meet on the
    // same temp path, or one would publish the other's half-written seed.
    let tmp_path = {
        let mut nonce_bytes = [0u8; 8];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let (pid, nonce) = (std::process::id(), hex::encode(nonce_bytes));
        path.with_extension(format!("json.{pid}.{nonce}.tmp"))
    };
    {
        // The 0600 only takes effect when the open actually creates the file.
        // An existing temp file must never be reused. A leftover from a
        // crashed write, or one planted by another process, would otherwise
        // decide the seed's permissions, or redirect the write through a
        // symlink. Unlink first, then create exclusively — if anything races
        // us back onto the path, `create_new` fails instead of writing the
        // seed somewhere it does not belong.
        match std::fs::remove_file(&tmp_path) {
            Ok(()) => (),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
            Err(err) => return Err(err),
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        // Something racing us onto our own temp path is not the seed file
        // being taken; don't let it read back as "a wallet already exists".
        let mut file = options.open(&tmp_path).map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                std::io::Error::other(format!("temp seed file {} is in use", tmp_path.display()))
            } else {
                err
            }
        })?;
        let () = std::io::Write::write_all(&mut file, &contents)?;
        let () = file.sync_all()?;
    }
    // First writer wins, decided by the kernel rather than by a check the
    // losers can slip past.
    let published = std::fs::hard_link(&tmp_path, path);
    // The temp file is a second on-disk copy of the seed either way; failing
    // to unlink it leaves a stale 0600 file, nothing worse.
    let _unlinked = std::fs::remove_file(&tmp_path);
    let () = published?;
    let dir = std::fs::File::open(path.parent().expect("seed file path has a parent"))?;
    dir.sync_all()
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bip39::{Language, Mnemonic};

    use super::{EncryptedMnemonic, KdfParams, Seed, SeedStore, error};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cusf-enforcer-seed-store-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // The all-zeros BIP39 test vector; any valid mnemonic works here.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon about";

    /// A second seed insert must be rejected with `AlreadyExists`, so a repeated
    /// `CreateWallet` surfaces `AlreadyExists` rather than storing two seeds.
    #[tokio::test]
    async fn insert_seed_rejects_a_second_seed() {
        let dir = temp_dir("already-exists");
        let store = SeedStore::new(&dir);
        let mnemonic = Mnemonic::parse_in(Language::English, TEST_MNEMONIC).unwrap();

        store
            .insert_seed(Seed::Plaintext(&mnemonic), None)
            .await
            .unwrap();
        let err = store
            .insert_seed(Seed::Plaintext(&mnemonic), None)
            .await
            .expect_err("second insert must fail");
        assert!(matches!(err, error::InsertSeed::AlreadyExists));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Stores constructed independently — as two processes would be — must
    /// not both accept a seed. The in-process lock cannot see them, so the
    /// publish itself has to be first-writer-wins: exactly one insert
    /// succeeds, the rest are told the wallet already exists, and the seed
    /// left on disk is the winner's.
    #[test]
    fn concurrent_stores_do_not_overwrite_each_others_seed() {
        // Distinct BIP39 test vectors, so a lost race shows up as the wrong
        // seed and not just as a second `Ok`.
        const MNEMONICS: [&str; 4] = [
            TEST_MNEMONIC,
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ];

        let seed_dir = temp_dir("concurrent-insert");
        let start = std::sync::Barrier::new(MNEMONICS.len());
        let (dir, barrier) = (seed_dir.as_path(), &start);
        let results: Vec<Result<String, error::InsertSeed>> = std::thread::scope(|scope| {
            let handles: Vec<_> = MNEMONICS
                .into_iter()
                .map(|mnemonic| {
                    scope.spawn(move || {
                        let mnemonic = Mnemonic::parse_in(Language::English, mnemonic).unwrap();
                        let store = SeedStore::new(dir);
                        // Line the inserts up on the check they must not all
                        // pass.
                        let _released = barrier.wait();
                        let inserted = store.insert_seed(Seed::Plaintext(&mnemonic), None);
                        futures::executor::block_on(inserted).map(|()| mnemonic.to_string())
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        });

        let winners: Vec<&String> = results
            .iter()
            .filter_map(|result| result.as_ref().ok())
            .collect();
        assert_eq!(winners.len(), 1, "exactly one insert may succeed");
        let winner = winners[0].clone();
        for result in &results {
            assert!(
                matches!(result, Ok(_) | Err(error::InsertSeed::AlreadyExists)),
                "the losers must be told the wallet already exists"
            );
        }

        let store = SeedStore::new(dir);
        let stored = futures::executor::block_on(store.read_mnemonic())
            .unwrap()
            .expect("the winner's seed must be on disk")
            .left()
            .expect("the seed was plaintext");
        assert_eq!(stored.to_string(), winner, "the winner's seed must survive");
        std::fs::remove_dir_all(&seed_dir).ok();
    }

    /// A recorded birthday round-trips; absence stays absent; and a seed
    /// file written before the field existed reads back as `None`.
    #[tokio::test]
    async fn birthday_height_roundtrip_and_backcompat() {
        let dir = temp_dir("birthday");
        let store = SeedStore::new(&dir);
        let mnemonic = Mnemonic::parse_in(Language::English, TEST_MNEMONIC).unwrap();
        store
            .insert_seed(Seed::Plaintext(&mnemonic), Some(958_537))
            .await
            .unwrap();
        assert_eq!(
            store.read_birthday_height().await.unwrap(),
            Some(958_537),
            "birthday must round-trip"
        );
        drop(store);
        std::fs::remove_dir_all(&dir).ok();

        // Restored seed: no birthday.
        let dir = temp_dir("birthday-none");
        let store = SeedStore::new(&dir);
        store
            .insert_seed(Seed::Plaintext(&mnemonic), None)
            .await
            .unwrap();
        assert_eq!(store.read_birthday_height().await.unwrap(), None);

        // Pre-birthday seed file (field absent entirely) must parse as None.
        let raw = std::fs::read_to_string(dir.join("seed.json")).unwrap();
        assert!(
            !raw.contains("birthday_height"),
            "None must not be serialized"
        );
        assert!(store.read_mnemonic().await.unwrap().is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The seed file must not be readable by other users.
    #[cfg(unix)]
    #[tokio::test]
    async fn seed_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = temp_dir("permissions");
        let store = SeedStore::new(&dir);
        let mnemonic = Mnemonic::parse_in(Language::English, TEST_MNEMONIC).unwrap();
        store
            .insert_seed(Seed::Plaintext(&mnemonic), None)
            .await
            .unwrap();

        let mode = std::fs::metadata(dir.join("seed.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A world-readable temp file left over from a crashed write (or planted)
    /// must not become the seed file's permissions.
    #[cfg(unix)]
    #[tokio::test]
    async fn stale_temp_file_does_not_widen_seed_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = temp_dir("stale-tmp");
        let tmp_path = dir.join("seed.json.tmp");
        std::fs::write(&tmp_path, b"stale").unwrap();
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o666)).unwrap();

        let store = SeedStore::new(&dir);
        let mnemonic = Mnemonic::parse_in(Language::English, TEST_MNEMONIC).unwrap();
        store
            .insert_seed(Seed::Plaintext(&mnemonic), None)
            .await
            .unwrap();

        let mode = std::fs::metadata(dir.join("seed.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "stale temp file must not be reused");
        assert_eq!(
            store
                .read_mnemonic()
                .await
                .unwrap()
                .unwrap()
                .left()
                .unwrap()
                .to_string(),
            TEST_MNEMONIC,
            "the stale contents must not survive into the seed file"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An encrypted seed records the cost it was stretched with.
    #[tokio::test]
    async fn encrypted_seed_round_trips_its_kdf_cost() {
        let mnemonic = Mnemonic::parse_in(Language::English, TEST_MNEMONIC).unwrap();

        let dir = temp_dir("kdf-current");
        let store = SeedStore::new(&dir);
        let encrypted = EncryptedMnemonic::encrypt(&mnemonic, "pw", KdfParams::CURRENT).unwrap();
        store
            .insert_seed(Seed::Encrypted(&encrypted), None)
            .await
            .unwrap();
        let read = store
            .read_mnemonic()
            .await
            .unwrap()
            .unwrap()
            .right()
            .expect("seed was encrypted");
        assert_eq!(read.kdf, KdfParams::CURRENT, "the cost must round-trip");
        assert_eq!(read.decrypt("pw").unwrap().to_string(), TEST_MNEMONIC);
        std::fs::remove_dir_all(&dir).ok();
    }
}
