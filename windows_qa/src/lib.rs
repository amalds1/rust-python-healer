//! Fail-closed structural PE64 preflight. No binaries are loaded or executed.
//! Authenticode, hash-pinning, ACLs and runtime compatibility require
//! separate Windows-native qualification and do NOT follow from this parser.

const MAX_PE_BYTES: usize = 64 * 1024 * 1024;
const PE64_MAGIC: u16 = 0x020b;
const X86_64_MACHINE: u16 = 0x8664;
const EXECUTABLE_IMAGE: u16 = 0x0002;
const DLL_IMAGE: u16 = 0x2000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pe64Inspection {
    pub architecture: &'static str,
    pub sections: u16,
    pub subsystem: &'static str,
    pub size_of_image: u32,
    pub structural_only: bool,
    pub signature_verified: bool,
    pub binary_executed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeError {
    SizeBound,
    MissingDosSignature,
    InvalidPeOffset,
    MissingPeSignature,
    WrongArchitecture,
    InvalidSectionCount,
    NotExecutable,
    NotPe32Plus,
    TruncatedOptionalHeader,
    InvalidImageSize,
    InvalidSubsystem,
}

fn read_u16(bytes: &[u8], position: usize) -> Option<u16> {
    let end = position.checked_add(2)?;
    Some(u16::from_le_bytes(bytes.get(position..end)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8], position: usize) -> Option<u32> {
    let end = position.checked_add(4)?;
    Some(u32::from_le_bytes(bytes.get(position..end)?.try_into().ok()?))
}

pub fn inspect_pe64_x64(bytes: &[u8]) -> Result<Pe64Inspection, PeError> {
    if !(128..=MAX_PE_BYTES).contains(&bytes.len()) {
        return Err(PeError::SizeBound);
    }
    if &bytes[..2] != b"MZ" {
        return Err(PeError::MissingDosSignature);
    }
    let pe_offset = read_u32(bytes, 0x3c).ok_or(PeError::InvalidPeOffset)? as usize;
    // Disallow overlapping DOS header and zero-filled payload tricks.
    if pe_offset < 64 || pe_offset.checked_add(24).is_none_or(|x| x > bytes.len()) {
        return Err(PeError::InvalidPeOffset);
    }
    if bytes.get(pe_offset..pe_offset + 4) != Some(&b"PE\0\0"[..]) {
        return Err(PeError::MissingPeSignature);
    }
    let coff = pe_offset + 4;
    if read_u16(bytes, coff) != Some(X86_64_MACHINE) {
        return Err(PeError::WrongArchitecture);
    }
    let sections = read_u16(bytes, coff + 2).ok_or(PeError::InvalidSectionCount)?;
    if !(1..=96).contains(&sections) {
        return Err(PeError::InvalidSectionCount);
    }
    let characteristics = read_u16(bytes, coff + 18).ok_or(PeError::NotExecutable)?;
    if characteristics & EXECUTABLE_IMAGE == 0 || characteristics & DLL_IMAGE != 0 {
        return Err(PeError::NotExecutable);
    }
    let optional_size = read_u16(bytes, coff + 16).ok_or(PeError::TruncatedOptionalHeader)? as usize;
    let optional = coff + 20;
    if optional_size < 112
        || optional.checked_add(optional_size).is_none_or(|x| x > bytes.len())
    {
        return Err(PeError::TruncatedOptionalHeader);
    }
    if read_u16(bytes, optional) != Some(PE64_MAGIC) {
        return Err(PeError::NotPe32Plus);
    }
    let size_of_image = read_u32(bytes, optional + 56).ok_or(PeError::InvalidImageSize)?;
    if size_of_image == 0 || size_of_image > 1024 * 1024 * 1024 {
        return Err(PeError::InvalidImageSize);
    }
    let subsystem = match read_u16(bytes, optional + 68) {
        Some(2) => "windows_gui",
        Some(3) => "windows_console",
        _ => return Err(PeError::InvalidSubsystem),
    };
    Ok(Pe64Inspection {
        architecture: "windows_x86_64",
        sections,
        subsystem,
        size_of_image,
        structural_only: true,
        signature_verified: false,
        binary_executed: false,
    })
}

/// Accept only an ASCII basename with the project's reserved executable prefix.
/// This is a lexical preflight, not proof that the real Windows path is safe
/// against reparse points, hardlinks or malicious same-user mutations.
pub fn validate_release_basename(value: &str) -> bool {
    let Some(stem) = value.strip_suffix(".exe") else {
        return false;
    };
    (10..=95).contains(&stem.len())
        && stem.starts_with("rph-")
        && stem.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        && stem.bytes().any(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut data = vec![0_u8; 512];
        data[..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&128_u32.to_le_bytes());
        data[128..132].copy_from_slice(b"PE\0\0");
        let coff = 132;
        data[coff..coff + 2].copy_from_slice(&X86_64_MACHINE.to_le_bytes());
        data[coff + 2..coff + 4].copy_from_slice(&2_u16.to_le_bytes());
        data[coff + 16..coff + 18].copy_from_slice(&240_u16.to_le_bytes());
        data[coff + 18..coff + 20].copy_from_slice(&EXECUTABLE_IMAGE.to_le_bytes());
        let optional = coff + 20;
        data[optional..optional + 2].copy_from_slice(&PE64_MAGIC.to_le_bytes());
        data[optional + 56..optional + 60].copy_from_slice(&8192_u32.to_le_bytes());
        data[optional + 68..optional + 70].copy_from_slice(&3_u16.to_le_bytes());
        data
    }

    #[test]
    fn accepts_x64_pe32_plus_exe_structurally_only() {
        let report = inspect_pe64_x64(&fixture()).unwrap();
        assert_eq!(report.architecture, "windows_x86_64");
        assert_eq!(report.sections, 2);
        assert!(!report.signature_verified);
        assert!(!report.binary_executed);
    }

    #[test]
    fn rejects_bad_dos_magic() {
        let mut image = fixture();
        image[0] = b'Q';
        assert_eq!(inspect_pe64_x64(&image), Err(PeError::MissingDosSignature));
    }

    #[test]
    fn rejects_bad_pe_offset() {
        let mut image = fixture();
        image[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(inspect_pe64_x64(&image), Err(PeError::InvalidPeOffset));
    }

    #[test]
    fn rejects_bad_pe_signature() {
        let mut image = fixture();
        image[128..132].copy_from_slice(b"NOPE");
        assert_eq!(inspect_pe64_x64(&image), Err(PeError::MissingPeSignature));
    }

    #[test]
    fn rejects_arm64_binary_on_x64_only_target() {
        let mut image = fixture();
        image[132..134].copy_from_slice(&0xaa64_u16.to_le_bytes());
        assert_eq!(inspect_pe64_x64(&image), Err(PeError::WrongArchitecture));
    }

    #[test]
    fn rejects_pe32_executable() {
        let mut image = fixture();
        image[152..154].copy_from_slice(&0x010b_u16.to_le_bytes());
        assert_eq!(inspect_pe64_x64(&image), Err(PeError::NotPe32Plus));
    }

    #[test]
    fn rejects_dll_even_when_executable_bit_present() {
        let mut image = fixture();
        image[150..152].copy_from_slice(&(EXECUTABLE_IMAGE | DLL_IMAGE).to_le_bytes());
        assert_eq!(inspect_pe64_x64(&image), Err(PeError::NotExecutable));
    }

    #[test]
    fn rejects_zero_sections() {
        let mut image = fixture();
        image[134..136].copy_from_slice(&0_u16.to_le_bytes());
        assert_eq!(inspect_pe64_x64(&image), Err(PeError::InvalidSectionCount));
    }

    #[test]
    fn rejects_missing_optional_header() {
        let mut image = fixture();
        image[148..150].copy_from_slice(&0_u16.to_le_bytes());
        assert_eq!(inspect_pe64_x64(&image), Err(PeError::TruncatedOptionalHeader));
    }

    #[test]
    fn rejects_efi_subsystem() {
        let mut image = fixture();
        image[220..222].copy_from_slice(&10_u16.to_le_bytes());
        assert_eq!(inspect_pe64_x64(&image), Err(PeError::InvalidSubsystem));
    }

    #[test]
    fn rejects_zero_image_size() {
        let mut image = fixture();
        image[208..212].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(inspect_pe64_x64(&image), Err(PeError::InvalidImageSize));
    }

    #[test]
    fn rejects_tiny_and_too_large_inputs() {
        assert_eq!(inspect_pe64_x64(&[0_u8; 3]), Err(PeError::SizeBound));
        assert_eq!(inspect_pe64_x64(&vec![0_u8; MAX_PE_BYTES + 1]), Err(PeError::SizeBound));
    }

    #[test]
    fn enforces_restricted_versioned_basename() {
        assert!(validate_release_basename("rph-0_28_0-win64.exe"));
        for name in [
            "CON.exe", "evil.exe:stream", "../../rph.exe", "rph-backup.exe. ",
            "rph-backup.dll", "C:\\Temp\\rph.exe", "rph-a.exe/", "rph-é.exe",
            "rph..exe", "rph-a.exe", "rph-a;whoami.exe", "rph-Z.exe",
        ] {
            assert!(!validate_release_basename(name), "incorrectly accepted {name:?}");
        }
    }
}
