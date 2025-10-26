use binaryninja::is_database;
use binaryninja::project::Project;
use rusqlite::{
    types::{FromSql, FromSqlError, ValueRef},
    Connection, Result,
};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

const SQL_GET_ORIGINAL_FILE_ID: &str =
    "SELECT value FROM global WHERE name = 'project_binary_id' LIMIT 1";

#[derive(Debug)]
pub struct ProjectBinary {
    pub header: [u8; 4], // first 4 bytes
    pub content: String, // remaining bytes as UTF-8 string
}

pub fn get_original_file_id(db: &str) -> Result<Option<ProjectBinary>> {
    let conn = Connection::open(db)?;

    let result = conn.query_row(SQL_GET_ORIGINAL_FILE_ID, [], |row| {
        let data: Vec<u8> = row.get(0)?;
        if data.len() < 4 {
            log::warn!("Invalid binary data: too short ({} bytes)", data.len());
            return Err(rusqlite::Error::InvalidQuery);
        }

        let mut header = [0u8; 4];
        header.copy_from_slice(&data[..4]);
        let content_bytes = &data[4..];
        let mut content = String::from_utf8_lossy(content_bytes).to_string();
        if content.starts_with('"') {
            if let Some(content1) = content.strip_prefix('"') {
                if content1.ends_with('"') {
                    if let Some(content2) = content1.strip_suffix('"') {
                        content = content2.to_string();
                    }
                }
            }
        }

        Ok(ProjectBinary { header, content })
    });

    match result {
        Ok(pb) => Ok(Some(pb)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn get_project_bndb_files(proj: &Project) -> Vec<String> {
    proj.files()
        .iter()
        .filter(|x| is_database(x.path_on_disk().unwrap().as_path()))
        .map(|pf| pf.id()) // each ProjectFile has its own id
        .collect()
}

pub fn is_project_folder_empty_of_files(proj: &Project, folder_id: &str) -> bool {
    !proj.files().iter().any(|project_file_ref| {
        // project_file_ref is a Ref<ProjectFile>
        let file = project_file_ref.as_ref();
        file.folder()
            .map(|folder_ref| folder_ref.as_ref().id() == folder_id)
            .unwrap_or(false)
    })
}

pub fn is_project_folder_empty_of_folders(proj: &Project, folder_id: &str) -> bool {
    !proj.folders().iter().any(|project_folder_ref| {
        let folder = project_folder_ref.as_ref();
        folder
            .parent()
            .map(|folder_ref| folder_ref.as_ref().id() == folder_id)
            .unwrap_or(false)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn get_original_file_id_from_bndb(db_path: *const c_char) -> *const c_char {
    if db_path.is_null() {
        log::error!("get_original_file_id_from_bndb: null db_path");
        return CString::new("").unwrap().into_raw();
    }

    let c_str = unsafe { CStr::from_ptr(db_path) };
    let db = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            log::error!("get_original_file_id_from_bndb: invalid UTF-8 in db_path");
            return CString::new("").unwrap().into_raw();
        }
    };

    match get_original_file_id(db) {
        Ok(Some(pb)) => CString::new(pb.content)
            .unwrap_or_else(|_| CString::new("").unwrap())
            .into_raw(),
        Ok(None) => CString::new("").unwrap().into_raw(),
        Err(e) => {
            log::error!("get_original_file_id_from_bndb: {e}");
            CString::new("").unwrap().into_raw()
        }
    }
}
