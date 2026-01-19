#[macro_use]
extern crate custom_error;

use binaryninja::background_task::BackgroundTask;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::{
    register_command, register_command_for_project, Command, ProjectCommand,
};
use binaryninja::is_database;
use binaryninja::metadata::Metadata;
use binaryninja::project::Project;
use binaryninja::rc::Ref;
use binaryninja::settings::Settings;
use rayon::prelude::*;
use regex::Regex;
use serde_json;
use serde_json::json;
use std;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::spawn;
use yara_x;

mod yarax;
use crate::yarax::{
    build_path_get_next_folder, count_folders, get_all_meta_file_rules, FileHits, MetaRule, Rules,
    Scanner,
};

mod bndb;
use crate::bndb::{
    get_original_file_id, get_project_bndb_files, is_project_folder_empty_of_files,
    is_project_folder_empty_of_folders,
};

static PLUGIN_NAME: &str = "BinYars";
static PLUGIN_SETTING_DIR: &str = "BinYars Settings.Yara-X Directory.dir";
static PLUGIN_SETTING_EMPTY_DIRY: &str = "BinYars Settings.Oracle of Order.empty_dir";
static PLUGIN_RULES_SERIALIZED_FILE: &str = "yarax.compiled.bin";
static PLUGIN_SETTING_STRING_VAR_LIMIT: &str = "BinYars Settings.Yara-X String Var.limit";

custom_error! {pub BinYarsError
    SerdeJsonError{source: serde_json::Error} = "Error ",
    YaraScanError{source: yara_x::ScanError} = "Error scanning file with the yara rules",
    FileError{source: std::io::Error} = "Error reading yara rule file",
    YaraRulesDeserilizationError{source: yara_x::errors::SerializationError} = "Error loading yara rules",
    RulesNotLoaded = "Rules not loaded",
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    plugin_init();
    true
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn UIPluginInit() -> bool {
    // Initialize logging
    // Register custom architectures, workflows, demanglers,
    // function recognizers, platforms and views!
    let settings = Settings::new();

    if !settings.contains(PLUGIN_SETTING_DIR) {
        let yarax_rules_dir = json!({
            "title" : "Set YARA-X Rules Directory",
            "type" : "string",
            "default" : "",
            "description" : "YARA-X rules directory to be used for scanning.",
        });
        settings.register_setting_json(PLUGIN_SETTING_DIR, &yarax_rules_dir.to_string());
    }

    let remove_empty_project_folders = json!({
        "title" : "Enable Delete Empty Project Folders",
        "type" : "boolean",
        "default" : false,
        "description" : "After Oracle of Order, remove any now empty project folders",
    });
    settings.register_setting_json(
        PLUGIN_SETTING_EMPTY_DIRY,
        &remove_empty_project_folders.to_string(),
    );

    let limit_string_var_matches_returned = json!({
        "title" : "Set YARA-X String Match Limit",
        "type" : "number",
        "default" : 20,
        "description" : "Restrict YARA-X rule string pattern matching capture to this number (it's per string var in the rule). Set to 0 to capture all of the string pattern matches from the rule. This does not effect the rule, just the json results stored in Binary Ninja. Warning, when set to 0 this can have adverse affects on Binary Ninja's performance.",
    });
    settings.register_setting_json(
        PLUGIN_SETTING_STRING_VAR_LIMIT,
        &limit_string_var_matches_returned.to_string(),
    );

    plugin_init();
    tracing::info!("{} Rust plugin component loaded!\n", PLUGIN_NAME);
    true
}

fn plugin_init() {
    binaryninja::tracing_init!(PLUGIN_NAME);

    register_command(
        &format!("{PLUGIN_NAME}\\Compile Rules"),
        "YaraX Rules",
        RuleCompileCommand {},
    );

    register_command_for_project(
        &format!("{PLUGIN_NAME}\\Brew (Compile)"),
        "YaraX Rules",
        ProjectRuleCompileCommand {},
    );

    register_command_for_project(
        &format!("{PLUGIN_NAME}\\Scanning Sage (Scan Only)"),
        "YaraX Scan Only",
        ScanCommand {},
    );
    register_command_for_project(
        &format!("{PLUGIN_NAME}\\Oracle of Order (Scan + Sort)"),
        "YaraX ALL The Things!",
        SortCommand {},
    );

    let yara_x_version = env!("YARA_X_VERSION");
    tracing::debug!("Using yara-x version: {}", yara_x_version);
}

/*****************************************************
************** Compile Yara-X Command ****************
*****************************************************/

struct ProjectRuleCompileCommand;

impl ProjectCommand for ProjectRuleCompileCommand {
    fn action(&self, _proj: &Project) {
        let rule_folder = Settings::new().get_string(PLUGIN_SETTING_DIR);

        if rule_folder.trim().is_empty() {
            tracing::error!(
                "Rules folder path is empty — check settings for `{}`",
                PLUGIN_SETTING_DIR
            );
            return;
        }

        let yara = yarax::Rules::new(PLUGIN_RULES_SERIALIZED_FILE, rule_folder.as_str());
        spawn(move || {
            let task = BackgroundTask::new("BinYars start", true);
            let res = yara.compile_and_save(&task);
            match res {
                Ok(_) => task.finish(),
                Err(e) => {
                    tracing::error!("Error processing {PLUGIN_NAME} files: {e:?}");
                    task.set_progress_text(&format!("{PLUGIN_NAME} Error: {e}"));
                    task.finish();
                }
            }
        });
    }

    fn valid(&self, proj: &Project) -> bool {
        proj.is_open()
    }
}

struct RuleCompileCommand;

impl Command for RuleCompileCommand {
    fn action(&self, _view: &BinaryView) {
        let rule_folder = Settings::new().get_string(PLUGIN_SETTING_DIR);

        if rule_folder.trim().is_empty() {
            tracing::error!(
                "Rules folder path is empty — check settings for `{}`",
                PLUGIN_SETTING_DIR
            );
            return;
        }

        let yara = yarax::Rules::new(PLUGIN_RULES_SERIALIZED_FILE, rule_folder.as_str());
        spawn(move || {
            let task = BackgroundTask::new("BinYars start", true);
            let res = yara.compile_and_save(&task);
            match res {
                Ok(_) => task.finish(),
                Err(e) => {
                    tracing::error!("Error processing {PLUGIN_NAME} files: {e:?}");
                    task.set_progress_text(&format!("{PLUGIN_NAME} Error: {e}"));
                    task.finish();
                }
            }
        });
    }

    fn valid(&self, view: &BinaryView) -> bool {
        view.file().project_file().is_none()
    }
}

/*****************************************************
***************** San Only Command *******************
*****************************************************/

struct ScanCommand;

impl ProjectCommand for ScanCommand {
    fn action(&self, proj: &Project) {
        tracing::info!("Scanning project: {}", proj.name());
        let project = proj.to_owned();
        let rule_folder = Settings::new().get_string(PLUGIN_SETTING_DIR);
        let pattern_limit = Settings::new().get_integer(PLUGIN_SETTING_STRING_VAR_LIMIT);

        if rule_folder.trim().is_empty() {
            tracing::error!(
                "Rules folder path is empty — check settings for `{}`",
                PLUGIN_SETTING_DIR
            );
            return;
        }

        spawn(move || {
            let task = BackgroundTask::new("BinYars start", true);
            let res = scanonly(&task, &project, &rule_folder, pattern_limit);
            match res {
                Ok(_) => task.finish(),
                Err(e) => {
                    tracing::error!("Error processing {PLUGIN_NAME} files: {e:?}");
                    task.set_progress_text(&format!("{PLUGIN_NAME} Error: {e}"));
                    task.finish();
                }
            }
        });
    }

    fn valid(&self, proj: &Project) -> bool {
        proj.is_open()
    }
}

fn scanonly(
    task: &BackgroundTask,
    proj: &Project,
    rule_folder: &str,
    pattern_limit: u64,
) -> anyhow::Result<()> {
    task.set_progress_text(&format!("{} - Scanning Files Only", PLUGIN_NAME));
    let hits = scan_project(task, proj, rule_folder, pattern_limit);

    if task.is_cancelled() {
        tracing::info!("Task cancelled by user.");
        return Ok(()); // exit early
    }

    // Store YaraX Results in the Project Metadata
    task.set_progress_text(&format!(
        "{} - Storing YaraX results to the project metadata",
        PLUGIN_NAME
    ));
    let result_meta = get_all_meta_file_rules(&hits);
    save_results_to_project_metadata(proj, result_meta);

    tracing::info!("BinYars execution complete!");
    Ok(())
}

/*****************************************************
******************* Sort Command *********************
*****************************************************/

struct SortCommand;

impl ProjectCommand for SortCommand {
    fn action(&self, proj: &Project) {
        tracing::info!("Scanning project: {}", proj.name());
        let project = proj.to_owned();
        let rule_folder = Settings::new().get_string(PLUGIN_SETTING_DIR);
        let pattern_limit = Settings::new().get_integer(PLUGIN_SETTING_STRING_VAR_LIMIT);

        if rule_folder.trim().is_empty() {
            tracing::error!(
                "Rules folder path is empty — check settings for `{}`",
                PLUGIN_SETTING_DIR
            );
            return;
        }

        let remove_empty_folders = Settings::new().get_bool(PLUGIN_SETTING_EMPTY_DIRY);
        spawn(move || {
            let task = BackgroundTask::new("BinYars start", true);
            let res = sort_by_rule_folder_name(
                &task,
                &project,
                &rule_folder,
                remove_empty_folders,
                pattern_limit,
            );
            match res {
                Ok(_) => task.finish(),
                Err(e) => {
                    tracing::error!("Error processing {PLUGIN_NAME} files: {e:?}");
                    task.set_progress_text(&format!("{PLUGIN_NAME} Error: {e}"));
                    task.finish();
                }
            }
        });
    }

    fn valid(&self, proj: &Project) -> bool {
        proj.is_open()
    }
}

fn scan_project(
    task: &BackgroundTask,
    proj: &Project,
    rule_folder: &str,
    pattern_limit: u64,
) -> Vec<FileHits> {
    let rules = Rules::new(PLUGIN_RULES_SERIALIZED_FILE, &rule_folder.to_string());

    if !proj.is_open() {
        return Vec::new();
    }

    task.set_progress_text(&format!("{} - Starting Scans", PLUGIN_NAME));

    // Collect all files first
    let files: Vec<_> = proj
        .files()
        .iter()
        .filter_map(|f| {
            let fullpath = f.path_on_disk()?;
            let path_str = fullpath.as_path().to_str()?;
            if !is_database(fullpath.as_path()) {
                Some((path_str.to_string(), f.name(), f.id()))
            } else {
                None
            }
        })
        .collect();

    let total = files.len();
    let counter = Arc::new(AtomicUsize::new(0));

    let rules_arc = match rules.load() {
        Ok(r) => Arc::new(r), // wrap loaded rules in Arc
        Err(e) => {
            tracing::error!("Rules not loaded: {}", e);
            return Vec::new();
        }
    };

    // Scan in parallel
    let results: Vec<FileHits> = files
        .par_iter()
        .filter_map(|(path_str, name, id)| {
            if task.is_cancelled() {
                return None; // silently stop this worker
            }

            tracing::info!("   Scanning {}", name);

            let matches = Scanner::scan_file(
                rules_arc.clone(),
                path_str,
                name.clone(),
                id.clone(),
                pattern_limit,
            );

            // update progress counter
            let finished = counter.fetch_add(1, Ordering::SeqCst) + 1;
            let percent = (finished * 100) / total.max(1);
            task.set_progress_text(&format!("{} - Scanning {}% complete", PLUGIN_NAME, percent));

            // Only keep successful results
            match matches {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::error!("Skipping {} due to scan error: {}", name, e);
                    None
                }
            }
        })
        .collect();

    tracing::info!("Scan complete.");

    results
}

fn sort_by_rule_folder_name(
    task: &BackgroundTask,
    proj: &Project,
    rule_folder: &str,
    remove_empty_folders_setting: bool,
    pattern_limit: u64,
) -> anyhow::Result<()> {
    task.set_progress_text(&format!("{} - Scanning Files", PLUGIN_NAME));
    let hits = scan_project(task, proj, rule_folder, pattern_limit);

    if task.is_cancelled() {
        tracing::info!("Task cancelled by user.");
        return Ok(()); // exit early
    }

    // Build out the new folder sturcture base up on the yara_x BNFolder meta
    task.set_progress_text(&format!("{} - Building BNDB Folders", PLUGIN_NAME));
    move_files_into_folders(task, proj, &hits);

    if task.is_cancelled() {
        tracing::info!("Task cancelled by user.");
        return Ok(()); // exit early
    }

    // Move the bndb files to be next to their corrisponding binary
    task.set_progress_text(&format!("{} - Moving BNDB Files", PLUGIN_NAME));
    move_bndb_files_to_binary_file_location(task, &proj);

    if task.is_cancelled() {
        tracing::info!("Task cancelled by user.");
        return Ok(()); // exit early
    }

    // Remove any empty folder is the option is selected
    if remove_empty_folders_setting {
        task.set_progress_text(&format!("{} - Moving Unmatched Files", PLUGIN_NAME));
        move_unmatched_file_to_root_dir(&proj, &hits);

        if task.is_cancelled() {
            tracing::info!("Task cancelled by user.");
            return Ok(()); // exit early
        }

        tracing::info!(
            "Remove empty folders setting is {}, so removing empty folders",
            remove_empty_folders_setting
        );
        task.set_progress_text(&format!("{} - Removing Empty Folders", PLUGIN_NAME));
        remove_empty_folders(task, proj);
    }

    if task.is_cancelled() {
        tracing::info!("Task cancelled by user.");
        return Ok(()); // exit early
    }

    // Store YaraX Results in the Project Metadata
    task.set_progress_text(&format!(
        "{} - Storing YaraX results to the project metadata",
        PLUGIN_NAME
    ));
    let result_meta = get_all_meta_file_rules(&hits);
    save_results_to_project_metadata(proj, result_meta);

    tracing::info!("BinYars execution complete!");
    Ok(())
}

fn move_files_into_folders(task: &BackgroundTask, proj: &Project, hits: &[FileHits]) {
    tracing::info!("Mapping Files to Project Folders");
    let total = hits.len();
    let counter = Arc::new(AtomicUsize::new(0));
    hits.iter().for_each(|h| {
        let mut path: Vec<String> = Vec::new();

        loop {
            // Recompute counts using the current path as base_folders
            let counts = count_folders(&hits, path.clone());

            // Find the best folder for this file
            if let Some(next_folder) = build_path_get_next_folder(h, &path, &counts) {
                // Stop if folder already in path (avoid infinite loop)
                if path.contains(&next_folder) {
                    tracing::debug!(
                        "  {} Folder Already Exists {:?}",
                        h.file_id,
                        h.get_bn_folders()
                    );
                    break;
                }
                // capture folder to path
                path.push(next_folder.clone());
            } else {
                tracing::debug!(
                    "  {} No more folders to add {:?}",
                    h.file_id,
                    h.get_bn_folders()
                );
                break; // no more folders can be added
            }

            // Stop when we’ve collected all folders for this hit
            if path.len() == h.get_bn_folders().len() {
                tracing::debug!(
                    "  {} All Folders Collected {:?}",
                    h.file_id,
                    h.get_bn_folders()
                );
                break;
            }
        }

        tracing::debug!("  Final path for file {}: {:?}", h.file_id, path);
        let folder_id = create_project_folder_path(h, proj, path, &h.file_id);

        if let Some(file) = proj.file_by_id(&h.file_id) {
            if let Some(_) = proj.folder_by_id(&folder_id) {
                tracing::info!(
                    "  Moving {} -> {}",
                    file.name(),
                    proj.folder_by_id(&folder_id).unwrap().name().as_str()
                );

                file.set_folder(proj.folder_by_id(&folder_id).as_deref());

                if !contains_string(&file.description(), &h.description()) {
                    let removed_old_results = strip_binyar_block(&file.description());
                    file.set_description(&format!("{}\n{}", removed_old_results, &h.description()));
                }
            }
        } else {
            tracing::error!("  File {} not found to move", &h.file_id);
        }

        // update progress counter
        let finished = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let percent = (finished * 100) / total.max(1);
        task.set_progress_text(&format!(
            "{} - Sorting into Folders {}% complete",
            PLUGIN_NAME, percent
        ));
    });
}

fn save_results_to_project_metadata(proj: &Project, meta_results: HashMap<String, Vec<MetaRule>>) {
    match serde_json::to_string(&meta_results) {
        Ok(rh) => {
            let metadata: Ref<Metadata> = From::from(rh);
            proj.store_metadata(PLUGIN_NAME, &metadata);
            tracing::info!("Saved metadata results to project under '{}'", PLUGIN_NAME);
        }
        Err(e) => {
            tracing::error!("Failed to serialize metadata results: {}", e);
        }
    }
}

fn remove_empty_folders(task: &BackgroundTask, proj: &Project) {
    let folder_ids: Vec<String> = proj
        .folders()
        .iter()
        .filter_map(|folder_ref| {
            let folder = folder_ref.as_ref();
            let fid = folder.id();
            if is_project_folder_empty_of_files(proj, &fid) {
                if is_project_folder_empty_of_folders(proj, &fid) {
                    Some(fid)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    let total = folder_ids.len();
    let counter = Arc::new(AtomicUsize::new(0));

    tracing::info!("Deleting Empty Folders");
    folder_ids.into_iter().for_each(|id| {
        delete_folder_walk(proj, &id);

        let finished = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let percent = (finished * 100) / total.max(1);
        task.set_progress_text(&format!(
            "{} - Empty Folder Deletion {}% complete",
            PLUGIN_NAME, percent
        ));
    });
}

fn delete_folder_walk(proj: &Project, folder_id: &str) {
    if let Some(folder) = proj.folder_by_id(folder_id) {
        if is_project_folder_empty_of_files(proj, folder_id)
            && is_project_folder_empty_of_folders(proj, folder_id)
        {
            let f = folder.as_ref();
            match proj.delete_folder(f) {
                Ok(_) => tracing::info!("  Deleted folder {} ({})", f.name(), f.id()),
                Err(_) => tracing::error!("  Error deleting folder {} ({})", f.name(), f.id()),
            }
            if let Some(parent) = f.parent() {
                delete_folder_walk(proj, &parent.id());
            }
        }
    }
}

fn move_unmatched_file_to_root_dir(proj: &Project, hits: &[FileHits]) {
    // Collect all file_ids that appear in FileHits
    let hit_ids: std::collections::HashSet<_> = hits
        .iter()
        .filter_map(|h| {
            if h.sort() {
                Some(h.file_id.as_str())
            } else {
                None
            }
        })
        .collect();

    tracing::info!("Moving Unmatched Files");
    for file in proj.files().into_iter() {
        let fullpath = file.path_on_disk().unwrap();
        // Don't move the bndb files as they will be handled by a different function
        if !is_database(fullpath.as_path()) {
            if !hit_ids.contains(file.id().as_str()) {
                tracing::info!("  {} to root dir", file.id());
                file.set_folder(None);
            }
        }
    }
}

fn move_bndb_files_to_binary_file_location(task: &BackgroundTask, proj: &Project) {
    tracing::info!("Moving BNDB files");

    let bndb_files = get_project_bndb_files(proj);

    let total = bndb_files.len();
    let counter = Arc::new(AtomicUsize::new(0));

    bndb_files.par_iter().for_each(|id| {
        if task.is_cancelled() {
            return; // silently stop this worker
        }

        tracing::info!("  Found BNDB file {}", id);

        let Some(bndb_id) = proj.file_by_id(&id).map(|f| f.id()) else {
            tracing::error!("    Failed to get BNDB project file");
            return;
        };

        // Get path on disk
        let fullpath = match proj.file_by_id(&bndb_id).and_then(|f| f.path_on_disk()) {
            Some(p) => p,
            None => {
                tracing::error!("    Failed to get BNDB file path on disk");
                return;
            }
        };

        let Some(path_str) = fullpath.as_path().to_str() else {
            tracing::error!("    Failed to convert BNDB path to string");
            return;
        };

        tracing::debug!("    BNDB file path on disk: {}", path_str);

        let Ok(Some(original_file_id)) = get_original_file_id(path_str) else {
            tracing::error!("    Failed to get original file id from BNDB");
            return;
        };

        tracing::debug!("    Original file id: {}", original_file_id);

        // Get binary file again (short-lived borrow)
        let Some(binary_file_id) = proj.file_by_id(&original_file_id).map(|f| f.id()) else {
            tracing::error!(
                "    Could not find binary project file matching id: {}",
                original_file_id
            );
            return;
        };

        let (bndb_project_path, binary_project_path) = {
            let bndb_path = proj.file_by_id(&bndb_id).and_then(|f| {
                f.path_in_project()
                    .as_path()
                    .to_str()
                    .map(|s| s.to_string())
            });
            let binary_path = proj.file_by_id(&binary_file_id).and_then(|f| {
                f.path_in_project()
                    .as_path()
                    .to_str()
                    .map(|s| s.to_string())
            });

            match (bndb_path, binary_path) {
                (Some(a), Some(b)) => (a, b),
                _ => {
                    tracing::error!("    Failed to get project paths");
                    return;
                }
            }
        };

        if binary_project_path != bndb_project_path {
            tracing::debug!(
                "    Binary Project Path {} does NOT match BNDB Project Path {}",
                binary_project_path,
                bndb_project_path
            );

            let Some(binary_folder_id) = proj
                .file_by_id(&binary_file_id)
                .and_then(|f| f.folder().map(|fld| fld.id()))
            else {
                tracing::error!("    Binary file has no folder associated with it");
                return;
            };

            if let Some(bndb_file) = proj.file_by_id(&bndb_id) {
                bndb_file.set_folder(proj.folder_by_id(&binary_folder_id).as_deref());
                tracing::info!(
                    "    BinaryNinja DB file {} moved to folder {}",
                    bndb_file.name(),
                    proj.folder_by_id(&binary_folder_id)
                        .map(|f| f.name())
                        .unwrap_or_else(|| "<unknown>".to_string())
                );
            }
        } else {
            tracing::info!("    BinaryNinja DB file {} already in correct folder", id);
            return;
        }

        // update progress counter
        let finished = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let percent = (finished * 100) / total.max(1);
        task.set_progress_text(&format!(
            "{} - Moving bndb files {}% complete",
            PLUGIN_NAME, percent
        ));
    });
}

fn strip_binyar_block(input: &str) -> String {
    // Regex: match the start marker, everything in between, and the end marker
    let re = Regex::new(
        r"(?s)==============================\s*BinYar Rules\s*===========================.*?End BinYar Rules\s*=============================="
    ).unwrap();

    re.replace_all(input, "").trim().to_string()
}

fn contains_string(haystack: &str, needle: &str) -> bool {
    haystack.contains(needle)
}

fn create_project_folder_path<'a>(
    file_hits: &FileHits,
    proj: &Project,
    path: Vec<String>,
    file_id: &str,
) -> String {
    let mut pid = String::new();
    tracing::debug!("Path for {} : {}", file_id, path.join("/"));
    path.into_iter().for_each(|p| {
        if !p.is_empty() {
            if let Some(folder_id) = get_project_folder_id(proj, &p, &pid) {
                pid = folder_id
            } else {
                match proj.create_folder(proj.folder_by_id(&pid).as_deref(), &p, "") {
                    Ok(cf) => pid = cf.id(),
                    Err(_) => {
                        tracing::error!("Error creating project folder");
                    }
                }
            }

            file_hits.hits.iter().for_each(|hit| {
                if hit.has_description() {
                    let temp_folder = proj.folder_by_id(&pid).unwrap();
                    if hit.folder == temp_folder.name() {
                        if !contains_string(&temp_folder.description(), &hit.desc) {
                            temp_folder.set_description(&format!(
                                "{}\n{}",
                                &temp_folder.description(),
                                &hit.desc
                            ));
                            tracing::debug!(
                                "Folder {} Description set to {}",
                                pid,
                                temp_folder.description()
                            );
                        }
                    }
                }
            });
        }
    });
    let mut new_path: Vec<String> = Vec::new();
    walk_folder_path(proj, pid.to_string(), &mut new_path);
    pid
}

fn get_project_folder_id(proj: &Project, name: &str, parent_id: &str) -> Option<String> {
    let result = proj
        .folders()
        .iter()
        .find(|f| {
            if f.name() != name {
                return false;
            }
            match f.parent() {
                Some(fp) => fp.id() == parent_id,
                None => parent_id.is_empty(),
            }
        })
        .map(|folder| folder.id());

    if result.is_none() {
        tracing::debug!("Parent {} not found for {}", parent_id, name);
    }

    result
}

fn walk_folder_path(proj: &Project, pid: String, path: &mut Vec<String>) {
    if let Some(folder) = proj.folder_by_id(&pid) {
        path.push(folder.name());
        if let Some(parent) = folder.parent() {
            walk_folder_path(proj, parent.id(), path);
        } else {
            tracing::debug!("Reversed path: {}", path.join("/"));
        }
    }
}
