use std::{io::Read, num::ParseIntError};

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

#[derive(Debug, PartialEq, DekuRead, DekuWrite, DekuSize)]
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

fn slice_to_str(input: &[u8]) -> Result<&str, String> {
    let Ok(cstr) = std::ffi::CStr::from_bytes_until_nul(input) else {
        return Err(String::from("biem"));
    };

    cstr.to_str().map_err(|e| e.to_string())
}

impl TarHeader {
    fn name(&self) -> Result<&str, String> {
        slice_to_str(&self.name)
    }
    fn uname(&self) -> Result<&str, String> {
        slice_to_str(&self.uname)
    }
    fn gname(&self) -> Result<&str, String> {
        slice_to_str(&self.gname)
    }
    fn size(&self) -> Result<u64, String> {
        // octal string
        u64::from_str_radix(slice_to_str(&self.size)?, 8).map_err(|e: ParseIntError| e.to_string())
    }

    fn validate_magic(&self) -> Result<(), String> {
        // gnu docs say it should be null character but it is a space?
        if &self.magic != b"ustar " {
            return Err(String::from("invalid magic bytes"));
        }

        Ok(())
    }
}

fn parse_tar(reader: &mut dyn std::io::Read) {
    let mut empty_blocks = 0;
    loop {
        let mut block = [0u8; 512];
        reader.read_exact(&mut block).unwrap();

        if block == [0u8; 512] {
            empty_blocks += 1;
            if empty_blocks == 2 {
                break;
            }
            continue;
        }

        let tar = TarHeader::try_from(block.as_slice()).unwrap();

        tar.validate_magic().unwrap();

        dbg!(tar.name().unwrap());
        dbg!(tar.uname().unwrap());
        dbg!(tar.gname().unwrap());
        dbg!(tar.size().unwrap());

        let mut remaining_size = tar.size().unwrap();
        while remaining_size > 0 {
            let mut block = [0; 512];
            reader.read_exact(&mut block).unwrap();
            remaining_size = remaining_size.saturating_sub(512);

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
                print!("{}", i as char);
            }
            dbg!(count_zeroes);
        }
    }
}

#[test]
fn xdxd_test() {
    use std::fs::File;

    let mut file = File::options().read(true).open("archive.tar").unwrap();

    parse_tar(&mut file);

    panic!("oke");
}
