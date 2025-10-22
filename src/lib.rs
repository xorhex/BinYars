#[macro_use]
extern crate custom_error;

use binaryninja::background_task::BackgroundTask;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::{
    register_command, register_command_for_project, Command, ProjectCommand,
};
use binaryninja::is_database;
use binaryninja::logger::Logger;
use binaryninja::metadata::Metadata;
use binaryninja::project::Project;
use binaryninja::rc::Ref;
use binaryninja::settings::Settings;
use log::LevelFilter;
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

    plugin_init();
    log::info!("{} Rust plugin component loaded!\n", PLUGIN_NAME);
    true
}

fn plugin_init() {
    Logger::new(PLUGIN_NAME)
        .with_level(LevelFilter::Debug)
        .init();

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
    log::debug!("Using yara-x version: {}", yara_x_version);
}

/*****************************************************
************** Compile Yara-X Command ****************
*****************************************************/

struct ProjectRuleCompileCommand;

impl ProjectCommand for ProjectRuleCompileCommand {
    fn action(&self, _proj: &Project) {
        let rule_folder = Settings::new().get_string(PLUGIN_SETTING_DIR);
        let yara = yarax::Rules::new(PLUGIN_RULES_SERIALIZED_FILE, rule_folder.as_str());
        spawn(move || {
            let task = BackgroundTask::new("BinYars start", true);
            let res = yara.compile_and_save(&task);
            match res {
                Ok(_) => task.finish(),
                Err(e) => {
                    log::error!("Error processing {PLUGIN_NAME} files: {e:?}");
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
        let yara = yarax::Rules::new(PLUGIN_RULES_SERIALIZED_FILE, rule_folder.as_str());
        spawn(move || {
            let task = BackgroundTask::new("BinYars start", true);
            let res = yara.compile_and_save(&task);
            match res {
                Ok(_) => task.finish(),
                Err(e) => {
                    log::error!("Error processing {PLUGIN_NAME} files: {e:?}");
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
        log::info!("Scanning project: {}", proj.name());
        let project = proj.to_owned();
        let rule_folder = Settings::new().get_string(PLUGIN_SETTING_DIR);
        spawn(move || {
            let task = BackgroundTask::new("BinYars start", true);
            let res = scanonly(&task, &project, &rule_folder);
            match res {
                Ok(_) => task.finish(),
                Err(e) => {
                    log::error!("Error processing {PLUGIN_NAME} files: {e:?}");
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

fn scanonly(task: &BackgroundTask, proj: &Project, rule_folder: &str) -> anyhow::Result<()> {
    task.set_progress_text(&format!("{} - Scanning Files Only", PLUGIN_NAME));
    let hits = scan_project(task, proj, rule_folder);

    if task.is_cancelled() {
        log::info!("Task cancelled by user.");
        return Ok(()); // exit early
    }

    // Store YaraX Results in the Project Metadata
    task.set_progress_text(&format!(
        "{} - Storing YaraX results to the project metadata",
        PLUGIN_NAME
    ));
    let result_meta = get_all_meta_file_rules(&hits);
    save_results_to_project_metadata(proj, result_meta);

    log::info!("BinYars execution complete!");
    Ok(())
}

/*****************************************************
******************* Sort Command *********************
*****************************************************/

struct SortCommand;

impl ProjectCommand for SortCommand {
    fn action(&self, proj: &Project) {
        log::info!("Scanning project: {}", proj.name());
        let project = proj.to_owned();
        let rule_folder = Settings::new().get_string(PLUGIN_SETTING_DIR);
        let remove_empty_folders = Settings::new().get_bool(PLUGIN_SETTING_EMPTY_DIRY);
        spawn(move || {
            let task = BackgroundTask::new("BinYars start", true);
            let res = sort_by_rule_folder_name(&task, &project, &rule_folder, remove_empty_folders);
            match res {
                Ok(_) => task.finish(),
                Err(e) => {
                    log::error!("Error processing {PLUGIN_NAME} files: {e:?}");
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

/// Scans all files in a Binary Ninja project using YARA rules from the specified folder.
///
/// This function performs the following steps:
/// 1. Loads serialized YARA rules from the given `rule_folder`.
/// 2. Iterates over all files in the `proj` that are not databases.
/// 3. Scans each file in parallel for matches against the loaded YARA rules.
/// 4. Updates the progress text on the provided `task` for UI feedback.
/// 5. Handles cancellation gracefully by stopping ongoing scans.
///
/// # Parameters
/// - `task`: Reference to a `BackgroundTask` used for updating progress and checking cancellation.
/// - `proj`: Reference to the `Project` containing files to be scanned.
/// - `rule_folder`: Path to the folder containing serialized YARA rules.
///
/// # Returns
/// - A `Vec<FileHits>` containing all successful scan results for the project files.
/// - Returns an empty vector if the project is not open, if rules fail to load, or if all files fail scanning.
///
/// # Behavior
/// - Skips files that are considered databases (via `is_database` check).
/// - Logs progress for each file scanned, including scan errors and cancellations.
/// - Scans are performed in parallel for efficiency using `par_iter`.
/// - Progress percentage is calculated and updated based on the number of files processed.
///
/// # Example
/// ```no_run
/// let task = BackgroundTask::new();
/// let proj = Project::open("my_project.bndb");
/// let rule_folder = "yara_rules";
/// let hits = scan_project(&task, &proj, rule_folder);
/// println!("Found {} files with matches", hits.len());
/// ```
fn scan_project(task: &BackgroundTask, proj: &Project, rule_folder: &str) -> Vec<FileHits> {
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
            log::error!("Rules not loaded: {}", e);
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

            log::info!("   Scanning {}", name);

            let matches = Scanner::scan_file(rules_arc.clone(), path_str, name.clone(), id.clone());

            // update progress counter
            let finished = counter.fetch_add(1, Ordering::SeqCst) + 1;
            let percent = (finished * 100) / total.max(1);
            task.set_progress_text(&format!("{} - Scanning {}% complete", PLUGIN_NAME, percent));

            // Only keep successful results
            match matches {
                Ok(v) => Some(v),
                Err(e) => {
                    log::error!("Skipping {} due to scan error: {}", name, e);
                    None
                }
            }
        })
        .collect();

    log::info!("Scan complete.");

    results
}

/// Sorts project files according to YARA rule folder names and updates the Binary Ninja project structure.
///
/// This function performs several steps to organize files within a project based on YARA rules:
/// 1. Scans the project for files matching the specified `rule_folder`.
/// 2. Builds and moves files into Binary Ninja Database (BNDB) folders according to rule metadata.
/// 3. Moves unmatched files to the project root directory.
/// 4. Moves BNDB files to their corresponding binary file locations.
/// 5. Optionally removes empty folders if `remove_empty_folders_setting` is true.
/// 6. Stores the results in the project's metadata.
///
/// At multiple points, the function checks if the `task` has been cancelled and will exit early if so.
///
/// # Parameters
/// - `task`: Reference to a `BackgroundTask` used for reporting progress and checking for cancellation.
/// - `proj`: Reference to the `Project` that contains the files to be sorted.
/// - `rule_folder`: Path to the folder containing YARA rules to guide file organization.
/// - `remove_empty_folders_setting`: If `true`, empty folders will be removed after sorting.
///
/// # Returns
/// - `Ok(())` if the sorting and metadata update completes successfully or the task is cancelled.
/// - Returns an `anyhow::Result::Err` only if any underlying operations fail.
///
/// # Behavior
/// - Updates progress text at each major step for UI feedback.
/// - Handles task cancellation gracefully by exiting early at multiple checkpoints.
/// - Logs informative messages for each operation, including task cancellation, folder removal, and completion.
///
/// # Example
/// ```no_run
/// let task = BackgroundTask::new();
/// let proj = Project::open("my_project.bndb");
/// let rule_folder = "yara_rules";
/// sort_by_rule_folder_name(&task, &proj, rule_folder, true).unwrap();
/// ```
fn sort_by_rule_folder_name(
    task: &BackgroundTask,
    proj: &Project,
    rule_folder: &str,
    remove_empty_folders_setting: bool,
) -> anyhow::Result<()> {
    task.set_progress_text(&format!("{} - Scanning Files", PLUGIN_NAME));
    let hits = scan_project(task, proj, rule_folder);

    if task.is_cancelled() {
        log::info!("Task cancelled by user.");
        return Ok(()); // exit early
    }

    // Build out the new folder sturcture base up on the yara_x BNFolder meta
    task.set_progress_text(&format!("{} - Building BNDB Folders", PLUGIN_NAME));
    move_files_into_folders(task, proj, &hits);

    if task.is_cancelled() {
        log::info!("Task cancelled by user.");
        return Ok(()); // exit early
    }

    // Move the bndb files to be next to their corrisponding binary
    task.set_progress_text(&format!("{} - Moving BNDB Files", PLUGIN_NAME));
    move_bndb_files_to_binary_file_location(&proj);

    if task.is_cancelled() {
        log::info!("Task cancelled by user.");
        return Ok(()); // exit early
    }

    // Remove any empty folder is the option is selected
    if remove_empty_folders_setting {
        task.set_progress_text(&format!("{} - Moving Unmatched Files", PLUGIN_NAME));
        move_unmatched_file_to_root_dir(&proj, &hits);

        if task.is_cancelled() {
            log::info!("Task cancelled by user.");
            return Ok(()); // exit early
        }

        log::info!(
            "Remove empty folders setting is {}, so removing empty folders",
            remove_empty_folders_setting
        );
        task.set_progress_text(&format!("{} - Removing Empty Folders", PLUGIN_NAME));
        remove_empty_folders(task, proj);
    }

    if task.is_cancelled() {
        log::info!("Task cancelled by user.");
        return Ok(()); // exit early
    }

    // Store YaraX Results in the Project Metadata
    task.set_progress_text(&format!(
        "{} - Storing YaraX results to the project metadata",
        PLUGIN_NAME
    ));
    let result_meta = get_all_meta_file_rules(&hits);
    save_results_to_project_metadata(proj, result_meta);

    log::info!("BinYars execution complete!");
    Ok(())
}

/// Organizes project files into folders based on pattern-matched results.
///
/// This function walks through each [`FileHits`] entry and determines the
/// correct folder hierarchy inside the project to place the corresponding file.
/// Folder creation and movement are driven by the structure of the matched
/// rules and metadata extracted from the analysis.
///
/// # Arguments
///
/// * `task` — A reference to the current [`BackgroundTask`] for reporting
///   progress updates during folder mapping and movement.
/// * `proj` — Reference to the active [`Project`] instance that manages files
///   and folders.
/// * `hits` — A list of [`FileHits`] objects, each representing metadata and
///   folder associations for a single file (e.g., parsed from rule matches).
///
/// # Behavior
///
/// 1. For each file hit:
///    - Builds a hierarchical folder path using the rule-derived folder structure.
///    - Uses [`count_folders`] and [`build_path_get_next_folder`] to determine
///      the most likely subfolder placement at each step.
///    - Stops when all possible folder levels for that hit are resolved or
///      when loops are detected.
/// 2. Calls [`create_project_folder_path`] to ensure all folders exist in the
///    project, creating missing ones if necessary.
/// 3. Moves the file into the resolved folder path using [`File::set_folder`].
/// 4. Updates the file’s description, removing any old BinYar result block and
///    appending the latest match description.
/// 5. Reports progress through the background task system.
///
/// # Logging
///
/// | Level | Purpose |
/// |--------|----------|
/// | `info` | High-level file movement and folder creation progress. |
/// | `debug` | Detailed per-file folder path decisions and hierarchy tracing. |
/// | `error` | When a file or folder cannot be found or moved. |
///
/// # Progress
///
/// The function calculates a completion percentage based on how many
/// [`FileHits`] have been processed and updates `task.set_progress_text()`
/// accordingly.
///
/// # Example
///
/// ```rust
/// move_files_into_folders(&task, &proj, &hits);
/// // Logs and progress updates will show folder creation and file movement.
/// ```
///
/// # Related Functions
///
/// - [`create_project_folder_path`]: Creates missing folders for a given path.
/// - [`strip_binyar_block`]: Removes previous analysis result sections.
/// - [`contains_string`]: Detects if a file’s description already includes the
///   same rule output.
///
/// # Errors
///
/// This function logs errors but does not return them.  
/// - Missing files or folders are logged and skipped.  
/// - Folder creation or movement failures do not stop processing of other files.
///
/// # Notes
///
/// - BNDB (Binary Ninja Database) files are **not** processed here — they are
///   handled separately by [`move_bndb_files_to_binary_file_location`].
/// - Recursive folder path resolution ensures proper nesting but includes
///   loop detection to prevent infinite recursion.
///
/// # See Also
///
/// - [`BackgroundTask`]
/// - [`Project`]
/// - [`FileHits`]
/// - [`create_project_folder_path`]
/// - [`strip_binyar_block`]
fn move_files_into_folders(task: &BackgroundTask, proj: &Project, hits: &[FileHits]) {
    log::info!("Mapping Files to Project Folders");
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
                    log::debug!(
                        "  {} Folder Already Exists {:?}",
                        h.file_id,
                        h.get_bn_folders()
                    );
                    break;
                }
                // capture folder to path
                path.push(next_folder.clone());
            } else {
                log::debug!(
                    "  {} No more folders to add {:?}",
                    h.file_id,
                    h.get_bn_folders()
                );
                break; // no more folders can be added
            }

            // Stop when we’ve collected all folders for this hit
            if path.len() == h.get_bn_folders().len() {
                log::debug!(
                    "  {} All Folders Collected {:?}",
                    h.file_id,
                    h.get_bn_folders()
                );
                break;
            }
        }

        log::debug!("  Final path for file {}: {:?}", h.file_id, path);
        let folder_id = create_project_folder_path(h, proj, path, &h.file_id);

        if let Some(file) = proj.file_by_id(&h.file_id) {
            if let Some(_) = proj.folder_by_id(&folder_id) {
                log::info!(
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
            log::error!("  File {} not found to move", &h.file_id);
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

/// Saves rule metadata results into the Binary Ninja project metadata store.
///
/// This function serializes a mapping of rule results into JSON and writes
/// it to the project's metadata under the plugin’s namespace (`PLUGIN_NAME`).
/// This allows later retrieval of analysis results or rule-based metadata.
///
/// # Arguments
///
/// * `proj` — Reference to the current [`Project`] where the metadata will be stored.  
/// * `meta_results` — A [`HashMap`] mapping from a string key (such as a file ID
///   or rule name) to a list of [`MetaRule`] objects representing the results
///   of the rule evaluation or analysis.
///
/// # Behavior
///
/// 1. Converts the `meta_results` structure into a JSON string using
///    [`serde_json::to_string`].  
/// 2. Wraps the JSON string in a [`Metadata`] object (`Ref<Metadata>`).  
/// 3. Stores the metadata in the project using [`Project::store_metadata`].  
///
/// If serialization fails, the function logs an error and does **not** modify
/// the project metadata.
///
/// # Logging
///
/// - `info`: Not used directly here, but other components may rely on the
///   metadata being updated.  
/// - `error`: Logged if JSON serialization fails, including the reason returned
///   by `serde_json`.
///
/// # Errors
///
/// This function will log but silently continue on serialization failure.
/// The project state remains unchanged in that case.
///
/// # Example
///
/// ```rust
/// let mut meta_results = HashMap::new();
/// meta_results.insert("file_123".to_string(), vec![MetaRule::new("ExampleRule", "Matched")]);
///
/// save_results_to_project_metadata(&proj, meta_results);
/// // The serialized results are now stored under PLUGIN_NAME in project metadata.
/// ```
///
/// # See Also
///
/// - [`Project::store_metadata`]
/// - [`serde_json`]
/// - [`MetaRule`]
fn save_results_to_project_metadata(proj: &Project, meta_results: HashMap<String, Vec<MetaRule>>) {
    match serde_json::to_string(&meta_results) {
        Ok(rh) => {
            let metadata: Ref<Metadata> = From::from(rh);
            proj.store_metadata(PLUGIN_NAME, &metadata);
            log::info!("Saved metadata results to project under '{}'", PLUGIN_NAME);
        }
        Err(e) => {
            log::error!("Failed to serialize metadata results: {}", e);
        }
    }
}

/// Removes all **empty folders** from a Binary Ninja project.
///
/// This function scans the project for folders that contain:
/// - **no files**, and  
/// - **no subfolders**  
///
/// It then deletes each such folder, updating task progress as it proceeds.
///
/// Internally, it uses [`delete_folder_walk`] to recursively delete
/// any empty parent folders as well.
///
/// # Arguments
///
/// * `task` — A [`BackgroundTask`] used to report progress back to the Binary Ninja UI.  
/// * `proj` — Reference to the current [`Project`].
///
/// # Behavior
///
/// 1. Iterates over all folders in the project.
/// 2. Filters out those that contain **no files** and **no subfolders**.
/// 3. Deletes each folder using [`delete_folder_walk`], which also
///    recursively removes any empty parent folders.
/// 4. Tracks progress using an atomic counter and updates the
///    task’s progress text with a completion percentage.
///
/// # Logging
///
/// - **Info:** Logs the start of deletion and each folder being processed.
/// - **Debug:** Can show detailed folder paths (depending on log configuration).
///
/// # Concurrency
///
/// - Thread-safe: uses [`Arc`] and [`AtomicUsize`] to safely track
///   progress across concurrent operations if extended in the future.
/// - Currently processes folders sequentially in a `for_each` loop.
///
/// # Example
///
/// ```rust
/// remove_empty_folders(&task, &proj);
/// // Deletes all empty folders and updates progress in Binary Ninja UI.
/// ```
///
/// # Related
///
/// - [`delete_folder_walk`]
/// - [`is_project_folder_empty_of_files`]
/// - [`is_project_folder_empty_of_folders`]
///
/// # Notes
///
/// - Safe to call multiple times — already-removed folders are simply ignored.
/// - Excludes any folder that contains files or nested subfolders.
/// - Progress is shown as percentage of folders processed, not actual
///   deletion count.
///
/// # See Also
///
/// [`Project::folders`], [`Project::delete_folder`]
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

    log::info!("Deleting Empty Folders");
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

/// Recursively deletes **empty folders** from a Binary Ninja project.
///
/// This function walks upward through the project’s folder hierarchy,
/// deleting the specified folder (and its ancestors) if they contain
/// **no files** and **no subfolders**.
///
/// The walk continues until it encounters a parent folder that is not empty,
/// or the root of the project is reached.
///
/// # Arguments
///
/// * `proj` — Reference to the current [`Project`].
/// * `folder_id` — The ID of the folder to check and potentially delete.
///
/// # Behavior
///
/// 1. Checks if the folder with `folder_id` exists in the project.
/// 2. If it exists:
///     - Verifies the folder is empty of files using [`is_project_folder_empty_of_files`].
///     - Verifies it is empty of subfolders using [`is_project_folder_empty_of_folders`].
/// 3. If both conditions hold true, deletes the folder via [`Project::delete_folder`].
/// 4. Recursively calls itself on the **parent folder**, continuing cleanup upward.
/// 5. Logs all operations for traceability.
///
/// # Logging
///
/// - **Info:** When a folder is successfully deleted.
/// - **Error:** When deletion fails.
/// - **None:** For skipped non-empty folders.
///
/// # Example
///
/// ```rust
/// delete_folder_walk(&proj, "folder_123");
/// // Deletes `folder_123` and any empty parent folders.
/// ```
///
/// # Notes
///
/// - This is a **safe recursive cleanup** function.
/// - Does **not** attempt to delete folders containing any files or subfolders.
/// - Safe to call repeatedly; once folders are gone, further calls simply no-op.
///
/// # Related
///
/// - [`is_project_folder_empty_of_files`]
/// - [`is_project_folder_empty_of_folders`]
/// - [`Project::delete_folder`]
fn delete_folder_walk(proj: &Project, folder_id: &str) {
    if let Some(folder) = proj.folder_by_id(folder_id) {
        if is_project_folder_empty_of_files(proj, folder_id)
            && is_project_folder_empty_of_folders(proj, folder_id)
        {
            let f = folder.as_ref();
            match proj.delete_folder(f) {
                Ok(_) => log::info!("  Deleted folder {} ({})", f.name(), f.id()),
                Err(_) => log::error!("  Error deleting folder {} ({})", f.name(), f.id()),
            }
            if let Some(parent) = f.parent() {
                delete_folder_walk(proj, &parent.id());
            }
        }
    }
}

/// Moves all project files that have **no corresponding scan results**
/// (i.e., files not appearing in any [`FileHits`]) to the **root directory**
/// of the project.
///
/// This function helps clean up project folder structures after a YARA scan
/// by ensuring that only files with matched rules remain in subfolders,
/// while unmatched files are relocated to the root.
///
/// # Arguments
///
/// * `proj` — A reference to the current [`Project`] being organized.
/// * `hits` — A slice of [`FileHits`] containing scan results for files.
///
/// # Behavior
///
/// 1. Builds a `HashSet` of all file IDs that have associated YARA hits
///    **and** contain at least one non-empty Binary Ninja folder path (sort).
/// 2. Iterates through every file in the project.
/// 3. Skips `.bndb` database files (they’re handled separately).
/// 4. Moves unmatched files (not in `hit_ids`) to the project root.
/// 5. Logs each move operation for traceability.
///
/// # Logging
///
/// - **Info:** When moving an unmatched file or starting the process.
/// - **Debug:** Can be added if needed for inspecting hit ID sets.
/// - **Error:** None are expected; failures are silently ignored.
///
/// # Example
///
/// ```rust
/// move_unmatched_file_to_root_dir(&proj, &scan_results);
/// // Moves all files without hits to the root folder.
/// ```
///
/// # Notes
///
/// - The helper function [`is_database`] should detect BNDB files.
/// - [`FileHits::sort`] returns true if there are any folders the
///   file to be moved to
///
/// # Related
///
/// - [`move_bndb_files_to_binary_file_location`] handles `.bndb` file placement.
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

    log::info!("Moving Unmatched Files");
    for file in proj.files().into_iter() {
        let fullpath = file.path_on_disk().unwrap();
        // Don't move the bndb files as they will be handled by a different function
        if !is_database(fullpath.as_path()) {
            if !hit_ids.contains(file.id().as_str()) {
                log::info!("  {} to root dir", file.id());
                file.set_folder(None);
            }
        }
    }
}

/// Moves Binary Ninja database (`.bndb`) files in a project so that each one
/// is located in the same folder as its corresponding original binary file.
///
/// This function searches the project for all `.bndb` files, determines
/// the binary file each one was created from, and ensures that both files
/// share the same project folder. If the BNDB file is not in the same
/// folder, it is automatically moved there.
///
/// # Arguments
///
/// * `proj` — A reference to the current [`Project`] containing files and folders.
///
/// # Behavior
///
/// - Logs each discovered `.bndb` file.
/// - Attempts to read the BNDB file on disk to determine the original binary’s project ID.
/// - Compares the BNDB file’s folder with that of the corresponding binary.
/// - Moves the BNDB file into the binary’s folder if they differ.
/// - Emits detailed log messages for successes and errors.
///
/// # Logging
///
/// - **Info:** When a BNDB file is found or successfully moved.
/// - **Debug:** When full paths or IDs are discovered during matching.
/// - **Error:** When a file or path cannot be resolved.
///
/// # Example
///
/// ```rust
/// move_bndb_files_to_binary_file_location(&proj);
/// // Moves all BNDB files to align with their binary files’ locations.
/// ```
///
/// # Errors
///
/// This function does not return an error directly.  
/// Failures (e.g., file not found, missing path, etc.) are logged using `log::error!`.
///
/// # Notes
///
/// - The function assumes that each `.bndb` file stores metadata containing
///   the original binary’s project ID.
/// - It uses helper functions such as [`get_project_bndb_files`] and
///   [`get_original_file_id`] to identify and match files.
fn move_bndb_files_to_binary_file_location(proj: &Project) {
    log::info!("Moving BNDB files");

    for id in get_project_bndb_files(proj) {
        log::info!("  Found BNDB file {}", id);

        let Some(bndb_id) = proj.file_by_id(&id).map(|f| f.id()) else {
            log::error!("    Failed to get BNDB project file");
            continue;
        };

        // Get path on disk
        let fullpath = match proj.file_by_id(&bndb_id).and_then(|f| f.path_on_disk()) {
            Some(p) => p,
            None => {
                log::error!("    Failed to get BNDB file path on disk");
                continue;
            }
        };

        let Some(path_str) = fullpath.as_path().to_str() else {
            log::error!("    Failed to convert BNDB path to string");
            continue;
        };

        log::debug!("    BNDB file path on disk: {}", path_str);

        let Ok(Some(original_file_id)) = get_original_file_id(path_str) else {
            log::error!("    Failed to get original file id from BNDB");
            continue;
        };

        log::debug!("    Original file id: {}", original_file_id.content);

        // Get binary file again (short-lived borrow)
        let Some(binary_file_id) = proj.file_by_id(&original_file_id.content).map(|f| f.id())
        else {
            log::error!(
                "    Could not find binary project file for {}",
                original_file_id.content
            );
            continue;
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
                    log::error!("    Failed to get project paths");
                    continue;
                }
            }
        };

        if binary_project_path != bndb_project_path {
            log::debug!(
                "    Binary Project Path {} does NOT match BNDB Project Path {}",
                binary_project_path,
                bndb_project_path
            );

            let Some(binary_folder_id) = proj
                .file_by_id(&binary_file_id)
                .and_then(|f| f.folder().map(|fld| fld.id()))
            else {
                log::error!("    Binary file has no folder associated with it");
                continue;
            };

            if let Some(bndb_file) = proj.file_by_id(&bndb_id) {
                bndb_file.set_folder(proj.folder_by_id(&binary_folder_id).as_deref());
                log::info!(
                    "    BinaryNinja DB file {} moved to folder {}",
                    bndb_file.name(),
                    proj.folder_by_id(&binary_folder_id)
                        .map(|f| f.name())
                        .unwrap_or_else(|| "<unknown>".to_string())
                );
            }
        } else {
            log::info!("    BinaryNinja DB file {} already in correct folder", id);
        }
    }
}

/*
fn move_bndb_files_to_binary_file_location(proj: &Project) {
    log::info!("Moving bndb files");
    // Move BNDB file to sit next to their corrisponding file
    get_project_bndb_files(&proj).into_iter().for_each(|id| {
        // Get BNDB File
        log::info!("  Found bndb file {}", id);
        if let Some(bndb_proj_file) = &proj.file_by_id(&id) {
            // Get the Full path on Disk to BNDB file
            if let Some(fullpath) = bndb_proj_file.clone().path_on_disk() {
                // Get the path as string
                if let Some(path_str) = fullpath.as_path().to_str() {
                    // Read the BNDB file to get the Global project_binary_id
                    log::debug!("    BNDB file path on disk {}", path_str);
                    if let Some(pb) = get_original_file_id(&path_str) {
                        //get location of binary file
                        log::debug!("    Original file id {}", pb.content);
                        if let Some(binary_proj_file) = &proj.file_by_id(&pb.content) {
                            // if not at the same location as the bndb id
                            log::debug!("    Found original file named {}", binary_proj_file.name());
                            if let Some(bndb_project_path) =
                                bndb_proj_file.path_in_project().as_path().to_str()
                            {
                                if let Some(binary_proj_path) =
                                    binary_proj_file.path_in_project().as_path().to_str()
                                {
                                    if binary_proj_path != bndb_project_path {
                                        log::debug!("    Binary Project Path {} does NOT match BNDB Project Path {}", binary_proj_path, bndb_project_path);
                                        // move bndb id to binary id location
                                        bndb_proj_file.set_folder(proj.folder_by_id(&binary_proj_file.folder().unwrap().id()).as_deref());
                                        log::info!("    BinaryNinja DB file {} moved to {}", bndb_project_path, binary_proj_file.folder().unwrap().name());
                                    } else {
                                        log::info!("    BinaryNinja DB file {} does NOT need to be moved", bndb_project_path);
                                    }
                                } else {
                                    log::error!("    Failed to get binary_project_path");
                                }
                            } else {
                                log::error!("    Failed to get bndb_project_path");
                            }
                        } else {
                            log::error!("    Failed to get original file id from bndb");
                        }
                    } else {
                        log::error!("    Failed to get original file id");
                    }
                } else {
                    log::error!("    Failed to get bndb_proj_file path on disk string");
                }
            } else {
                log::error!("    Failed to get bndb_proj_file path on disk");
            }
        } else {
            log::error!("    Failed to get bndb_proj_file");
        }

    });
}
*/

/// Removes all text blocks between the BinYar rule markers (inclusive) from a given string.
///
/// This function searches for text sections that start with:
/// ```text
/// ==============================
/// BinYar Rules
/// ===========================
/// ```
/// and end with:
/// ```text
/// End BinYar Rules
/// ==============================
/// ```
///
/// Everything between (and including) these markers is removed from the string.
///
/// # Arguments
///
/// * `input` - The input text containing potential BinYar rule sections.
///
/// # Returns
///
/// A new `String` with all BinYar rule blocks removed and surrounding whitespace trimmed.
///
/// # Example
///
/// ```rust
/// let text = r#"
/// Header text
/// ==============================
/// BinYar Rules
/// ============================
/// some yara rule content
/// End BinYar Rules
/// ==============================
/// Footer text
/// "#;
///
/// let cleaned = strip_binyar_block(text);
/// assert!(cleaned.contains("Header text"));
/// assert!(cleaned.contains("Footer text"));
/// assert!(!cleaned.contains("BinYar Rules"));
/// ```
///
/// # Notes
///
/// - Uses a single-line (`(?s)`) regex flag so that `.` matches newlines.
/// - Will remove **all** matching rule blocks if multiple exist in the text.
fn strip_binyar_block(input: &str) -> String {
    // Regex: match the start marker, everything in between, and the end marker
    let re = Regex::new(
        r"(?s)==============================\s*BinYar Rules\s*===========================.*?End BinYar Rules\s*=============================="
    ).unwrap();

    re.replace_all(input, "").trim().to_string()
}

/// Checks whether a given substring (`needle`) exists within another string (`haystack`).
///
/// # Arguments
///
/// * `haystack` - The string to search within.
/// * `needle` - The substring to look for inside `haystack`.
///
/// # Returns
///
/// Returns `true` if `needle` is found anywhere in `haystack`, otherwise `false`.
///
/// # Example
///
/// ```rust
/// let text = "Binary Ninja is powerful";
/// assert!(contains_string(text, "Ninja"));
/// assert!(!contains_string(text, "Yara"));
/// ```
///
/// # Notes
///
/// This function performs a simple substring search using [`str::contains`],
/// which is case-sensitive and works efficiently for short text checks.
fn contains_string(haystack: &str, needle: &str) -> bool {
    haystack.contains(needle)
}

/// Ensures that a project folder path exists for a given file and updates folder descriptions based on metadata.
///
/// # Arguments
///
/// * `file_hits` - A [`FileHits`] reference containing metadata (`MetaRule`s) for the scanned file.
/// * `proj` - Reference to the active [`Project`] where folders are managed.
/// * `path` - A list (`Vec<String>`) representing the folder hierarchy to create or verify, in order (e.g., `["src", "yara", "rules"]`).
/// * `file_id` - The unique identifier of the file being processed.
///
/// # Returns
///
/// Returns the final folder ID (`String`) corresponding to the deepest folder in the constructed path.
///
/// # Behavior
///
/// This function walks through the provided `path` segments and ensures that each folder exists in the project:
///
/// 1. For each folder name:
///    - If the folder already exists under the current parent, it uses that folder’s ID.
///    - If it does not exist, it creates the folder using [`Project::create_folder`].
///
/// 2. After creating or retrieving a folder, it checks `file_hits.hits` for any [`MetaRule`]s whose `folder`
///    matches the current folder name:
///    - If the `MetaRule` has a non-empty description and it’s not already in the folder’s description,
///      it appends it (separated by a newline).
///
/// 3. Logs progress and updates using `log::debug!` and `log::error!`.
///
/// 4. At the end, reconstructs and logs the full reverse path using [`walk_folder_path`].
///
/// # Example
///
/// ```rust
/// let path = vec!["src".to_string(), "rules".to_string()];
/// let folder_id = create_project_folder_path(&file_hits, &project, path, "file_123");
/// println!("Final folder ID: {}", folder_id);
/// ```
///
/// # Side Effects
///
/// - Creates missing folders within the project hierarchy.
/// - Updates folder descriptions when `MetaRule` descriptions are available.
/// - Logs debug and error messages.
///
/// # Errors
///
/// - Fails gracefully if folder creation fails (logs error but continues).
/// - Skips description updates for missing folders.
///
/// # Notes
///
/// - This function assumes `Project::create_folder` and `folder_by_id` are thread-safe or used in a single-threaded context.
/// - Empty folder names in the path are ignored.
/// - Descriptions are appended only if not already present to prevent duplication.
fn create_project_folder_path<'a>(
    file_hits: &FileHits,
    proj: &Project,
    path: Vec<String>,
    file_id: &str,
) -> String {
    let mut pid = String::new();
    log::debug!("Path for {} : {}", file_id, path.join("/"));
    path.into_iter().for_each(|p| {
        if !p.is_empty() {
            if let Some(folder_id) = get_project_folder_id(proj, &p, &pid) {
                pid = folder_id
            } else {
                match proj.create_folder(proj.folder_by_id(&pid).as_deref(), &p, "") {
                    Ok(cf) => pid = cf.id(),
                    Err(_) => {
                        log::error!("Error creating project folder");
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
                            log::debug!(
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

/// Retrieves the ID of a project folder that matches a given name and parent folder ID.
///
/// # Arguments
///
/// * `proj` - Reference to the current [`Project`] containing folders.
/// * `name` - The name of the folder to search for.
/// * `parent_id` - The ID of the expected parent folder.  
///   - If this is an empty string, the function searches for folders without a parent (root-level).
///
/// # Returns
///
/// Returns `Some(String)` containing the matching folder’s ID if found,  
/// or `None` if no folder matches both the name and parent ID.
///
/// # Behavior
///
/// The function iterates over all folders in the project and finds the first one that:
/// - Has the specified `name`, and  
/// - Has a parent folder whose ID matches `parent_id`, or no parent if `parent_id` is empty.
///
/// If no match is found, a debug log entry is recorded.
///
/// # Example
///
/// ```rust
/// if let Some(folder_id) = get_project_folder_id(&project, "src", "root_id") {
///     println!("Found folder ID: {}", folder_id);
/// } else {
///     println!("Folder not found");
/// }
/// ```
///
/// # Logging
///
/// Logs a debug message if no matching folder is found.
///
/// # Notes
///
/// - This function assumes folder names are not unique across different parent folders.
/// - Use both name and parent ID together for disambiguation.
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
        log::debug!("Parent {} not found for {}", parent_id, name);
    }

    result
}

/// Recursively walks up the folder hierarchy of a project to build the full path
/// from a given folder ID to the root.
///
/// # Arguments
///
/// * `proj` - Reference to the current [`Project`] containing folders.
/// * `pid` - The folder ID (`String`) to start walking from.
/// * `path` - A mutable vector used to collect folder names as the path is built.
///
/// # Behavior
///
/// This function performs a recursive traversal from the specified folder up through
/// its parent folders until the root is reached. Each folder name encountered is pushed
/// onto the provided `path` vector.
///
/// The resulting `path` will contain folder names in **reverse order** (i.e., from the
/// starting folder up to the root). You can reverse it afterward or join with a separator
/// to form a readable folder path.
///
/// # Example
///
/// ```rust
/// let mut path = Vec::new();
/// walk_folder_path(&project, "some_folder_id".to_string(), &mut path);
/// let full_path = path.iter().rev().cloned().collect::<Vec<_>>().join("/");
/// println!("Full folder path: {}", full_path);
/// ```
///
/// # Notes
///
/// - The function logs the reversed path (joined by "/") when it reaches the root folder.
/// - If the folder ID does not exist, nothing is added to `path`.
/// - Used for debugging purposes
fn walk_folder_path(proj: &Project, pid: String, path: &mut Vec<String>) {
    if let Some(folder) = proj.folder_by_id(&pid) {
        path.push(folder.name());
        if let Some(parent) = folder.parent() {
            walk_folder_path(proj, parent.id(), path);
        } else {
            log::debug!("Reversed path: {}", path.join("/"));
        }
    }
}
