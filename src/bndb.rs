use anyhow::{anyhow, Result};

use binaryninja::binary_view::BinaryViewExt;
use binaryninja::project::Project;
use binaryninja::{is_database, load_with_options};

pub fn get_original_file_id(db: &str) -> Result<Option<String>> {
    let bv = match load_with_options(db, false, Some("")) {
        Some(val) => val,
        None => return Ok(None),
    };

    let fmeta = bv.file();

    // `database()` returns Option<Ref<Database>>
    let Some(fdb) = fmeta.database() else {
        return Err(anyhow!("Database not found"));
    };

    let bn_str = match fdb.read_global("project_binary_id") {
        Some(val) => val,
        None => return Ok(None),
    };

    // Convert to &str, handling UTF-8 decoding errors
    let mut pbid = bn_str
        .to_str()
        .map_err(|e| anyhow!("Invalid UTF-8: {}", e))?
        .to_string();

    // Remove surrounding quotes if present
    if pbid.starts_with('"') && pbid.ends_with('"') && pbid.len() >= 2 {
        pbid = pbid[1..pbid.len() - 1].to_string();
    }

    Ok(Some(pbid))
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
