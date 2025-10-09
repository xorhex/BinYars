use binaryninja::is_database;
use binaryninja::project::Project;
use rusqlite::{
    types::{FromSql, FromSqlError, ValueRef},
    Connection, Result,
};

const SQL_GET_ORGINAL_FILE_ID: &str = "SELECT value FROM global WHERE name = 'project_binary_id'";

#[derive(Debug)]
pub struct ProjectBinary {
    pub header: [u8; 4], // first 4 bytes
    pub content: String, // remaining bytes as UTF-8 string
}

impl FromSql for ProjectBinary {
    fn column_result(value: ValueRef<'_>) -> Result<Self, FromSqlError> {
        match value {
            ValueRef::Blob(bytes) => {
                if bytes.len() < 4 {
                    return Err(FromSqlError::Other(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "blob too short",
                    ))));
                }

                let header: [u8; 4] = bytes[0..4]
                    .try_into()
                    .map_err(|_| FromSqlError::Other("failed to extract header".into()))?;

                let content_bytes = &bytes[4..];
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
            }
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

pub fn get_original_file_id(db: &str) -> Option<ProjectBinary> {
    // Open your SQLite database
    match Connection::open(db) {
        Ok(conn) => match conn.prepare(SQL_GET_ORGINAL_FILE_ID) {
            Ok(mut stmt) => match stmt.query_map([], |row| {
                let pb: rusqlite::Result<ProjectBinary> = row.get(0);
                pb
            }) {
                Ok(iter) => {
                    for pb in iter {
                        match pb {
                            Ok(pb) => {
                                log::debug!("Found pb");
                                return Some(pb);
                            }
                            Err(e) => {
                                log::error!("Error getting pb: {}", e);
                                return None;
                            }
                        }
                    }
                    return None;
                }
                Err(e) => {
                    log::error!("Error getting pb iter: {}", e);
                    return None;
                }
            },
            Err(e) => {
                log::error!("Error stmt: {}", e);
                return None;
            }
        },
        Err(e) => {
            log::error!("Error making connection: {}", e);
            return None;
        }
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
