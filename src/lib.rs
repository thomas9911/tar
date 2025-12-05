use std::{
    ffi::OsString,
    io::Write,
    num::ParseIntError,
    path::{Path, PathBuf},
    sync::Mutex,
};

use deku::prelude::*;

// {                              /* byte offset */
//   char name[100];               /*   0 */
//   char mode[8];                 /* 100 */
//   char uid[8];                  /* 108 */
//   char gid[8];                  /* 116 */
//   char size[12];                /* 124 */
//   char mtime[12];               /* 136 */
//   char chksum[8];               /* 148 */
//   char typeflag;                /* 156 */
//   char linkname[100];           /* 157 */
//   char magic[6];                /* 257 */
//   char version[2];              /* 263 */
//   char uname[32];               /* 265 */
//   char gname[32];               /* 297 */
//   char devmajor[8];             /* 329 */
//   char devminor[8];             /* 337 */
//   char prefix[155];             /* 345 */
// };

#[derive(Debug, PartialEq, DekuRead, DekuWrite, DekuSize, Clone)]
#[deku(endian = "big")]
pub struct TarHeader {
    name: [u8; 100],
    mode: u64,
    uid: u64,
    gid: u64,
    size: [u8; 12],
    mtime: [u8; 12],
    chksum: u64,
    typeflag: u8,
    linkname: [u8; 100],
    magic: [u8; 6],
    version: [u8; 2],
    uname: [u8; 32],
    gname: [u8; 32],
    devmajor: u64,
    devminor: u64,
    #[deku(pad_bytes_after = "12")]
    prefix: [u8; 155],
}

/// Tar bytes are `cstr`/`&[u8]` this struct contains the rust types
pub struct TarHeaderCastedFields<'a> {
    pub name: &'a str,
    pub uname: &'a str,
    pub gname: &'a str,
    pub size: u64,
    pub typeflag: TarFileType,
}

pub enum TarFileType {
    RegularFile,
    Link,
    SymTypeReserved,
    CharacterSpecial,
    BlockSpecial,
    Dir,
    FifoSpecial,
    ContTypeReserved,
    XHDType,
    XGLType,
}

fn slice_to_str(input: &[u8]) -> Result<&str, String> {
    let Ok(cstr) = std::ffi::CStr::from_bytes_until_nul(input) else {
        return Err(String::from("biem"));
    };

    cstr.to_str().map_err(|e| e.to_string())
}

impl TarHeader {
    pub fn name(&self) -> Result<&str, String> {
        slice_to_str(&self.name)
    }
    pub fn uname(&self) -> Result<&str, String> {
        slice_to_str(&self.uname)
    }
    pub fn gname(&self) -> Result<&str, String> {
        slice_to_str(&self.gname)
    }
    pub fn size(&self) -> Result<u64, String> {
        // octal string
        u64::from_str_radix(slice_to_str(&self.size)?, 8).map_err(|e: ParseIntError| e.to_string())
    }

    pub fn typeflag(&self) -> Result<TarFileType, String> {
        // from GNU docs
        let flag = match self.typeflag {
            b'0' | 0 => TarFileType::RegularFile,
            b'1' => TarFileType::Link,
            b'2' => TarFileType::SymTypeReserved,
            b'3' => TarFileType::CharacterSpecial,
            b'4' => TarFileType::BlockSpecial,
            b'5' => TarFileType::Dir,
            b'6' => TarFileType::FifoSpecial,
            b'7' => TarFileType::ContTypeReserved,
            b'x' => TarFileType::XHDType,
            b'g' => TarFileType::XGLType,
            _ => return Err(String::from("invalid typeflag header")),
        };

        Ok(flag)
    }

    pub fn casted_fields(&self) -> Result<TarHeaderCastedFields<'_>, String> {
        Ok(TarHeaderCastedFields {
            name: self.name()?,
            uname: self.uname()?,
            gname: self.gname()?,
            size: self.size()?,
            typeflag: self.typeflag()?,
        })
    }

    pub fn validate_magic(&self) -> Result<(), String> {
        // gnu docs say it should be null character but it is a space?
        if ![b"ustar ", b"ustar\0"].contains(&&self.magic) {
            return Err(String::from("invalid magic bytes"));
        }

        Ok(())
    }
}

pub fn list_files_in_tar(
    reader: &mut dyn std::io::Read,
) -> Result<impl Iterator<Item = String>, String> {
    struct FileNameIter {
        fs: NullFileSystem,
        offset: usize,
    }

    impl Iterator for FileNameIter {
        type Item = String;

        fn next(&mut self) -> Option<Self::Item> {
            let state = self.fs.state.lock().unwrap();

            let item = state
                .get(self.offset)
                .map(|x| x.tar.name().expect("checked earlier").to_owned());
            self.offset += 1;
            item
        }
    }

    let memory_fs = NullFileSystem::default();
    parse_tar(reader, &memory_fs)?;
    Ok(FileNameIter {
        fs: memory_fs,
        offset: 0,
    })
}

pub fn parse_tar(reader: &mut dyn std::io::Read, fs: &impl FileSystemImpl) -> Result<(), String> {
    const BLOCK_SIZE: usize = 512;
    const BLOCK_SIZE_U64: u64 = BLOCK_SIZE as u64;

    let mut empty_blocks = 0;
    loop {
        let mut block = [0u8; BLOCK_SIZE];
        reader.read_exact(&mut block).unwrap();

        if block == [0u8; BLOCK_SIZE] {
            empty_blocks += 1;
            if empty_blocks == 2 {
                // according to the spec the last part are two empty blocks
                break;
            }
            continue;
        }

        let tar = TarHeader::try_from(block.as_slice()).unwrap();

        tar.validate_magic()?;
        let casted_fields = tar.casted_fields()?;

        let mut file = fs.open(&tar, &casted_fields)?;

        let mut remaining_size = tar.size().unwrap();
        while remaining_size > 0 {
            let current_blocksize = if remaining_size >= BLOCK_SIZE_U64 {
                BLOCK_SIZE_U64
            } else {
                remaining_size
            } as usize;
            let mut block = [0; BLOCK_SIZE];
            reader.read_exact(&mut block).unwrap();
            remaining_size = remaining_size.saturating_sub(BLOCK_SIZE_U64);

            let mut count_zeroes = 0;
            for i in block {
                if i == b'\0' {
                    count_zeroes += 1;
                } else {
                    if count_zeroes != 0 {
                        dbg!(count_zeroes);
                    }
                    count_zeroes = 0;
                }
            }
            file.write_block(&block[..current_blocksize])?;
            dbg!(count_zeroes);
        }

        fs.save(file).unwrap();
    }
    Ok(())
}

enum ParseTarError {}

enum ParseTarResult<T> {
    Ok(T),
    Err(ParseTarError),
}

pub trait FileSystemImpl {
    type Writer: FileWriter;
    fn open<'a>(
        &self,
        tar_header: &'a TarHeader,
        casted_fields: &'a TarHeaderCastedFields<'a>,
    ) -> Result<Self::Writer, String>;
    fn save(&self, writer: Self::Writer) -> Result<(), String>;
}

pub trait FileWriter {
    fn write_block(&mut self, data: &[u8]) -> Result<(), String>;
}

#[cfg(feature = "filesystem")]
pub struct FileSystem {
    /// sets the gid uid in the tar file, false will just use the current user
    pub use_metadata: bool,
    start_folder: cap_std::fs::Dir,
}

#[cfg(feature = "filesystem")]
impl std::default::Default for FileSystem {
    fn default() -> Self {
        Self {
            use_metadata: false,
            start_folder: cap_std::fs::Dir::open_ambient_dir(".", cap_std::ambient_authority())
                .unwrap(),
        }
    }
}

#[cfg(feature = "filesystem")]
impl FileSystem {
    pub fn new<P: AsRef<Path>>(starting_dir: P) -> Self {
        FileSystem {
            start_folder: cap_std::fs::Dir::open_ambient_dir(
                starting_dir,
                cap_std::ambient_authority(),
            )
            .unwrap(),
            use_metadata: false,
        }
    }
}

#[cfg(feature = "filesystem")]
impl FileSystemImpl for FileSystem {
    type Writer = FileWrapper;

    fn open<'a>(
        &self,
        tar_header: &'a TarHeader,
        casted_fields: &'a TarHeaderCastedFields,
    ) -> Result<Self::Writer, String> {
        if self.use_metadata {
            todo!("implement setting the user of the file")
        } else {
            match casted_fields.typeflag {
                TarFileType::RegularFile => self
                    .start_folder
                    .create(casted_fields.name)
                    .map_err(|e| e.to_string())
                    .map(|x| FileWrapper::File(x)),
                TarFileType::Dir => self
                    .start_folder
                    .create_dir_all(casted_fields.name)
                    .map_err(|e| e.to_string())
                    .map(|_| FileWrapper::Dir),
                _ => Err(String::from(
                    "unable to create file with type other than file or dir",
                )),
            }
            // let dir = cap_std::fs::Dir::open_ambient_dir(&self.start_folder, self.ambient_authority);
            // let path = self.start_folder.join(casted_fields.name);
            // we probably need to make this safe, if name has .. or absolute path, it goes there.
            // std::fs::File::create(path).map_err(|e| e.to_string())
        }
    }

    fn save(&self, writer: Self::Writer) -> Result<(), String> {
        match writer {
            FileWrapper::File(mut writer) => Ok(writer.flush().map_err(|e| e.to_string())?),
            FileWrapper::Dir => Ok(()),
        }
    }
}

#[cfg(feature = "filesystem")]
pub enum FileWrapper {
    File(cap_std::fs::File),
    Dir,
}

#[cfg(feature = "filesystem")]
impl FileWriter for FileWrapper {
    fn write_block(&mut self, data: &[u8]) -> Result<(), String> {
        match self {
            FileWrapper::File(file) => file.write_all(data).map_err(|e| e.to_string()),
            FileWrapper::Dir => Err(String::from("unable to write to dir type")),
        }
    }
}

#[derive(Debug)]
pub struct MemoryFile {
    pub name: String,
    pub meta: TarHeader,
    pub data: Vec<u8>,
}

impl FileWriter for MemoryFile {
    fn write_block(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.data.extend_from_slice(bytes);

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MemoryFileSystem {
    pub state: Mutex<Vec<MemoryFile>>,
}

impl FileSystemImpl for MemoryFileSystem {
    type Writer = MemoryFile;
    fn open(
        &self,
        tar: &TarHeader,
        casted_fields: &TarHeaderCastedFields,
    ) -> Result<Self::Writer, String> {
        Ok(MemoryFile {
            name: casted_fields.name.to_string(),
            meta: tar.clone(),
            data: Vec::new(),
        })
    }

    fn save(&self, writer: Self::Writer) -> Result<(), String> {
        let mut lock = self.state.lock().expect("unable to acquire lock");

        lock.push(writer);

        Ok(())
    }
}

#[derive(Debug)]
pub struct NullFile {
    pub tar: TarHeader,
}

impl<'a> FileWriter for NullFile {
    fn write_block(&mut self, _bytes: &[u8]) -> Result<(), String> {
        Ok(())
    }
}

/// FileSystem that doesnt not store the contents of the file
#[derive(Debug, Default)]
pub struct NullFileSystem {
    pub state: Mutex<Vec<NullFile>>,
}

impl<'a> FileSystemImpl for NullFileSystem {
    type Writer = NullFile;
    fn open(
        &self,
        tar: &TarHeader,
        _casted_fields: &TarHeaderCastedFields,
    ) -> Result<Self::Writer, String> {
        let cloned_tar = tar.clone();
        Ok(NullFile { tar: cloned_tar })
    }

    fn save(&self, writer: Self::Writer) -> Result<(), String> {
        let mut lock = self.state.lock().expect("unable to acquire lock");

        lock.push(writer);

        Ok(())
    }
}

#[test]
fn xdxd_test() {
    use std::fs::File;

    #[derive(Debug, Default)]
    struct MockFile {
        name: String,
        data: String,
    }

    impl FileWriter for MockFile {
        fn write_block(&mut self, bytes: &[u8]) -> Result<(), String> {
            self.data.push_str(std::str::from_utf8(bytes).unwrap());

            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct MockFs {
        state: Mutex<Vec<MockFile>>,
    }

    impl FileSystemImpl for MockFs {
        type Writer = MockFile;
        fn open(
            &self,
            tar: &TarHeader,
            casted_fields: &TarHeaderCastedFields,
        ) -> Result<Self::Writer, String> {
            assert_eq!(tar.name().unwrap(), casted_fields.name);
            assert_eq!(tar.uname().unwrap(), casted_fields.uname);
            assert_eq!(tar.gname().unwrap(), casted_fields.gname);
            assert_eq!(tar.size().unwrap(), casted_fields.size);

            Ok(MockFile {
                name: casted_fields.name.to_string(),
                data: String::new(),
            })
        }

        fn save(&self, writer: Self::Writer) -> Result<(), String> {
            let mut lock = self.state.lock().unwrap();

            lock.push(writer);

            Ok(())
        }
    }

    let mut file = File::open("test/support/archive.tar").unwrap();

    let fs = MockFs::default();

    parse_tar(&mut file, &fs).unwrap();

    let lock = fs.state.lock().unwrap();
    assert_eq!(lock.len(), 5);
    let file_names: Vec<_> = lock.iter().map(|x| x.name.to_string()).collect();
    assert_eq!(
        file_names,
        vec![
            String::from("./archive/"),
            String::from("./archive/lorem.txt"),
            String::from("./archive/nested/"),
            String::from("./archive/nested/data.txt"),
            String::from("./archive/small.txt"),
        ]
    );
    let file_contents: Vec<_> = lock.iter().map(|x| x.data.to_string()).collect();

    assert!(file_contents[1].contains("END OF STRING"));
}

#[test]
fn list_file_test() {
    use std::fs::File;

    let mut file = File::open("test/support/archive.tar").unwrap();

    let file_names: Vec<_> = list_files_in_tar(&mut file).unwrap().collect();
    assert_eq!(
        file_names,
        vec![
            String::from("./archive/"),
            String::from("./archive/lorem.txt"),
            String::from("./archive/nested/"),
            String::from("./archive/nested/data.txt"),
            String::from("./archive/small.txt"),
        ]
    );
}

#[cfg(feature = "filesystem")]
#[test]
fn unpack_tar_into_temp_folder_test() {
    // copied from the rust docs
    fn visit_dirs(dir: &Path, cb: &dyn Fn(&std::fs::DirEntry)) -> std::io::Result<()> {
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    visit_dirs(&path, cb)?;
                } else {
                    cb(&entry);
                }
            }
        }
        Ok(())
    }

    use std::fs::File;

    let mut file = File::open("test/support/archive.tar").unwrap();
    let tmp_dir = tempfile::tempdir().unwrap();

    let tmp_dir_path = tmp_dir.path();
    let fs = FileSystem::new(tmp_dir_path);
    // tmp_dir.into_path();

    parse_tar(&mut file, &fs).unwrap();

    let files = Mutex::new(Vec::new());
    visit_dirs(tmp_dir_path, &|entry| {
        let path_parts = entry
            .path()
            .strip_prefix(tmp_dir_path)
            .unwrap()
            .iter()
            .map(|x| x.to_string_lossy().to_string())
            .collect::<Vec<String>>();
        files.lock().unwrap().push(path_parts)
    })
    .unwrap();
    let mut files = files.into_inner().unwrap();
    files.sort();

    assert_eq!(
        files,
        vec![
            vec!["archive", "lorem.txt"],
            vec!["archive", "nested", "data.txt"],
            vec!["archive", "small.txt"],
        ]
    )
}
