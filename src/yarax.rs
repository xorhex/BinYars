use anyhow::{anyhow, Result};
use binaryninja::background_task::BackgroundTask;
use log::info;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::Cursor;
use std::io::{Read, Write};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use string_builder::Builder;
use walkdir::WalkDir;
use yara_x;
use yara_x_fmt::Formatter;

custom_error! {pub BinYarsError
    SerdeJsonError{source: serde_json::Error} = "Error ",
    YaraScanError{source: yara_x::ScanError} = "Error scanning file with the yara rules",
    FileError{source: std::io::Error} = "Error reading yara rule file",
    YaraRulesDeserilizationError{source: yara_x::errors::SerializationError} = "Error loading yara rules",
    RulesNotLoaded = "Rules not loaded",
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Pattern {
    pub identifier: String,
    pub offset: usize,
    pub length: usize,
    pub data: String,
}

impl Pattern {
    pub fn new(name: String, offset: usize, length: usize, data: String) -> Self {
        Self {
            identifier: name,
            offset,
            length,
            data,
        }
    }

    pub fn description(&self) -> String {
        format!(
            "Identifier: {}\n  Offset: {}\n  Length: {}\n  Data: {}",
            self.identifier, self.offset, self.length, self.data
        )
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetaRule {
    pub rule: String,
    pub desc: String,
    pub console: Vec<HashMap<String, String>>,
    pub folder: String,
    pub identifiers: Vec<Pattern>,
}

impl MetaRule {
    pub fn new(
        rule: String,
        desc: String,
        folder: String,
        console: Vec<HashMap<String, String>>,
        identifiers: Vec<Pattern>,
    ) -> Self {
        Self {
            rule,
            desc,
            console,
            folder,
            identifiers,
        }
    }
    pub fn has_description(&self) -> bool {
        !self.desc.trim().is_empty()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileHits {
    pub hits: Vec<MetaRule>,
    pub file_id: String,
}

impl FileHits {
    pub fn new(file_id: String, hits: Vec<MetaRule>) -> Self {
        Self { file_id, hits }
    }

    pub fn get_bn_folders(&self) -> Vec<String> {
        let mut folders: Vec<String> = self.hits.iter().map(|hit| hit.folder.clone()).collect();

        // Remove duplicates
        folders.sort();
        folders.dedup();

        folders
    }

    pub fn sort(&self) -> bool {
        !self.get_bn_folders().join("").trim().is_empty()
    }

    pub fn description(&self) -> String {
        let mut builder = Builder::default();
        builder.append("\n==============================\n");
        builder.append("BinYar Rules\n");
        builder.append("===========================\n");
        builder.append("\n");

        self.hits.iter().for_each(|h| {
            builder.append("----------------------------\n");
            builder.append(format!("Rule: {}\n", h.rule));
            if h.has_description() {
                builder.append(format!("Description: {}\n", h.desc));
            }
            if !h.console.is_empty() {
                builder.append(format!("Console:\n"));
                for (_, map) in h.console.iter().enumerate() {
                    for (k, v) in map {
                        builder.append(format!("  {}: {}\n", k, v))
                    }
                }
            }
            h.identifiers.iter().for_each(|i| {
                builder.append(format!("Identifier: {}\n", i.identifier));
                builder.append(format!("  Offset: {}\n", i.offset));
                builder.append(format!("  Length: {}\n", i.length));
                builder.append(format!("  Data: {}\n", i.data));
            });
            builder.append("----------------------------\n");
            builder.append("\n");
        });

        builder.append("End BinYar Rules\n");
        builder.append("==============================\n");

        builder.string().unwrap()
    }
}

pub struct Rules {
    pub rule_folder: PathBuf,
    pub save_as: PathBuf,
}

impl Rules {
    pub fn new(compiled_rule_file: impl AsRef<Path>, rule_folder: impl AsRef<Path>) -> Self {
        let rule_folder = rule_folder.as_ref().to_path_buf();
        let save_as = rule_folder.join(&compiled_rule_file);

        Self {
            rule_folder,
            save_as,
        }
    }

    pub fn compile_and_save(&self, task: &BackgroundTask) -> anyhow::Result<()> {
        info!("Compiling yara-x rules in {:?}", self.rule_folder);
        let files: Vec<String> = WalkDir::new(&self.rule_folder)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .filter(|e| has_yara_extension(e.path()))
            .map(|e| e.path().to_string_lossy().into_owned())
            .collect();

        let mut compiler = yara_x::Compiler::new();

        for f in files {
            let mut file =
                File::open(&f).map_err(|e| anyhow::anyhow!("Failed to open file {}: {}", f, e))?;

            if task.is_cancelled() {
                log::info!("Task cancelled by user.");
                return Ok(()); // exit early
            }

            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .map_err(|e| anyhow::anyhow!("Failed to read file {}: {}", f, e))?;

            let source_code =
                yara_x::SourceCode::from(contents.as_str()).with_origin(&f.to_string());

            match compiler.add_source(source_code) {
                Ok(_) => {
                    log::info!("File {} compiled", &f);
                }
                Err(e) => {
                    log::error!("Error compiling rule {}\n{}", &f, e);
                }
            }

            if task.is_cancelled() {
                log::info!("Task cancelled by user.");
                return Ok(()); // exit early
            }
        }

        if task.is_cancelled() {
            log::info!("Task cancelled by user.");
            return Ok(()); // exit early
        }

        let mut built_rules = compiler.build();
        log::info!("YaraX rules built");

        if task.is_cancelled() {
            log::info!("Task cancelled by user.");
            return Ok(()); // exit early
        }

        let _ = self.save(&mut built_rules);
        log::info!("YaraX rules saved");

        Ok(())
    }

    fn save(&self, rules: &mut yara_x::Rules) -> Result<(), BinYarsError> {
        let fullname = self.save_as.to_str().unwrap();
        match File::create(fullname) {
            Ok(mut file) => {
                match rules.serialize() {
                    Ok(bytes) => {
                        // Write the byte data to the file
                        match file.write_all(&bytes) {
                            Ok(_) => {
                                info!("Compiled YaraX rules written successfully to {}", fullname);
                            }
                            Err(e) => {
                                return Err(BinYarsError::FileError { source: (e) });
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Error serializing yara rules : {}", e);
                        return Err(BinYarsError::YaraRulesDeserilizationError { source: (e) });
                    }
                }
            }
            Err(e) => {
                log::error!("Unable to create file : {}", e);
                return Err(BinYarsError::FileError { source: (e) });
            }
        }

        Ok(())
    }

    pub fn load(&self) -> Result<yara_x::Rules, BinYarsError> {
        let fullname = self
            .save_as
            .to_str()
            .ok_or_else(|| BinYarsError::FileError {
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid path string",
                ),
            })?;

        let mut file = File::open(fullname).map_err(|e| {
            log::error!("Error opening rule file ({}) : {}", fullname, e);
            BinYarsError::FileError { source: e }
        })?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).map_err(|e| {
            log::error!("Error reading file {}: {}", fullname, e);
            BinYarsError::FileError { source: e }
        })?;

        yara_x::Rules::deserialize(buffer).map_err(|e| {
            log::error!("Error loading rules: {}", e);
            BinYarsError::YaraRulesDeserilizationError { source: e }
        })
    }

    pub fn compile(rule: String) -> String {
        let mut compiler = yara_x::Compiler::new();

        let source_code = yara_x::SourceCode::from(rule.as_str());

        match compiler.add_source(source_code) {
            Ok(_) => "".to_string(),
            Err(e) => {
                log::error!("Error compiling rule\n{}", e);
                e.to_string()
            }
        }
    }

    pub fn format(rule: String) -> String {
        if Rules::compile(rule.clone()) == "" {
            let mut output = Cursor::new(Vec::new());

            match Formatter::new().format(rule.clone().as_bytes(), &mut output) {
                Ok(_) => {
                    if let Ok(s) = String::from_utf8(output.into_inner()) {
                        return s;
                    }
                }
                Err(_) => {}
            }
        }
        rule
    }
}

pub struct Scanner;

impl Scanner {
    pub fn module_info(bytes: &[u8]) -> String {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(r#"import "pe" import "elf" import "lnk" import "macho" import "dotnet" rule test {condition: true}"#)
            .unwrap();

        let rules = compiler.build();
        let mut scanner = yara_x::Scanner::new(&rules);
        let results = scanner.scan(bytes).unwrap();

        // Extract module information from the scan results
        let mut module_info_map: HashMap<String, Option<String>> = HashMap::new();

        log::info!("Rust Iterating Over Module Outputs");
        results.module_outputs().for_each(|(name, data)| {
            log::info!("Module: {}", name);
            log::info!("{:?}", data);
            module_info_map.insert(name.to_string(), Some(format!("{:?}", data)));
        });
        match serde_json::to_string(&module_info_map) {
            Ok(json) => json.to_string(),
            Err(_) => String::new(),
        }
    }

    pub fn scan_bytes(rules: yara_x::Rules, bytes: &[u8]) -> String {
        let mut scanner = yara_x::Scanner::new(&rules);

        let logs: Arc<Mutex<Vec<HashMap<String, String>>>> = Arc::new(Mutex::new(Vec::new()));
        let logs_for_cb = Arc::clone(&logs);

        scanner.console_log(
            move |msg| match parse_console_log_message(msg.to_string()) {
                Ok(parsed) => {
                    let mut logs = logs_for_cb.lock().unwrap();
                    logs.push(parsed);
                }
                Err(e) => {
                    log::debug!("   Failed to parse console log message '{}': {}", msg, e);
                }
            },
        );

        match scanner.scan(bytes) {
            Ok(hits) => {
                let results = hits
                    .matching_rules()
                    .map(|h| {
                        MetaRule::new(
                            h.identifier().to_string(),
                            get_metadata_string_field(h.metadata(), "Description")
                                .unwrap_or_default(),
                            get_metadata_string_field(h.metadata(), "BNFolder").unwrap_or_default(),
                            filter_logs_by_rule(Arc::clone(&logs), &h.identifier().to_string()),
                            get_patterns(h.patterns()),
                        )
                    })
                    .collect::<Vec<MetaRule>>();
                log::info!(
                    "Scanner found: {:?}",
                    results
                        .iter()
                        .map(|r| r.rule.clone())
                        .collect::<Vec<String>>(),
                );

                match serde_json::to_string(&results) {
                    Ok(rh) => rh,
                    Err(_) => String::new(),
                }
            }
            Err(e) => {
                log::error!("Error scanning bytes: {}", e);
                String::new()
            }
        }
    }

    pub fn scan_file(
        rules: Arc<yara_x::Rules>,
        file_path: &str,
        file_name: String,
        file_id: String,
    ) -> Result<FileHits, BinYarsError> {
        // Perform the scan
        Scanner::do_scan(&rules, file_path, file_name, file_id)
    }

    fn do_scan(
        arc_rules: &Arc<yara_x::Rules>,
        file_path: &str,
        file_name: String,
        file_id: String,
    ) -> Result<FileHits, BinYarsError> {
        let mut scanner = yara_x::Scanner::new(arc_rules);

        let logs: Arc<Mutex<Vec<HashMap<String, String>>>> = Arc::new(Mutex::new(Vec::new()));
        let logs_for_cb = Arc::clone(&logs);

        scanner.console_log(
            move |msg| match parse_console_log_message(msg.to_string()) {
                Ok(parsed) => {
                    let mut logs = logs_for_cb.lock().unwrap();
                    logs.push(parsed);
                }
                Err(e) => {
                    log::debug!("   Failed to parse console log message '{}': {}", msg, e);
                }
            },
        );

        match scanner.scan_file(file_path) {
            Ok(hits) => {
                let result = hits
                    .matching_rules()
                    .map(|h| {
                        MetaRule::new(
                            h.identifier().to_string(),
                            get_metadata_string_field(h.metadata(), "Description")
                                .unwrap_or_default(),
                            get_metadata_string_field(h.metadata(), "BNFolder").unwrap_or_default(),
                            filter_logs_by_rule(Arc::clone(&logs), &h.identifier().to_string()),
                            get_patterns(h.patterns()),
                        )
                    })
                    .collect::<Vec<MetaRule>>();
                log::debug!(
                    "Scanner found: {:?} for {}",
                    result
                        .iter()
                        .map(|r| r.rule.clone())
                        .collect::<Vec<String>>(),
                    file_id
                );

                Ok(FileHits::new(file_id.clone(), result))
            }
            Err(e) => {
                log::error!("Error scanning file {}: {}", file_name, e);
                Err(BinYarsError::YaraScanError { source: e })
            }
        }
    }
}

fn has_yara_extension(path: &Path) -> bool {
    match path.extension().and_then(|s| s.to_str()) {
        Some("yar") | Some("yara") => true,
        _ => false,
    }
}

/// Parses a specially formatted console log message into a JSON-like map.
///
/// Expected format:
/// ```text
/// TB|key:value|key2:value2|...
/// ```
///
/// # Example
/// ```
/// let msg = "TB|event:start|file:test.exe".to_string();
/// let map = parse_console_log_message(msg).unwrap();
/// assert_eq!(map.get("event"), Some(&"start".to_string()));
/// ```
pub fn parse_console_log_message(msg: String) -> Result<HashMap<String, String>> {
    let trimmed = msg.trim();

    // Must start with "TB|"
    if !trimmed.starts_with("BN|") {
        return Err(anyhow!("Message does not start with 'BN|'"));
    }

    // Remove prefix
    let content = &trimmed[3..]; // skip "TB|"

    // Split on '|'
    let parts: Vec<&str> = content.split('|').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return Err(anyhow!("No key/value pairs found after 'BN|'"));
    }

    let mut map = HashMap::new();

    for part in parts {
        // Ensure exactly one ':'
        let colon_count = part.matches(':').count();
        if colon_count != 1 {
            return Err(anyhow!(
                "Invalid field '{}': must contain exactly one ':'",
                part
            ));
        }

        // Split on ':'
        let mut split = part.splitn(2, ':');
        let key = split.next().unwrap().trim();
        let value = split.next().unwrap().trim();

        if key.is_empty() {
            return Err(anyhow!("Empty key in part '{}'", part));
        }

        map.insert(key.to_string(), value.to_string());
    }

    if !map.contains_key("rule") {
        return Err(anyhow!("Parsed log does not contain required key 'rule'"));
    }

    Ok(map)
}

/// Filters logs by `rule_name` and removes the "rule" key from each map
fn filter_logs_by_rule(
    logs: Arc<Mutex<Vec<HashMap<String, String>>>>,
    rule_name: &str,
) -> Vec<HashMap<String, String>> {
    let collected = logs.lock().unwrap().clone();

    collected
        .into_iter()
        .filter_map(|mut map| {
            // Only keep if the "rule" key matches
            if map.get("rule").map(|v| v == rule_name).unwrap_or(false) {
                map.remove("rule"); // remove the "rule" key
                log::debug!("   Rule name matched value: {}", rule_name);
                Some(map)
            } else {
                log::debug!("   No rule name matched value: {}", rule_name);
                None
            }
        })
        .collect()
}

fn get_patterns(patterns: yara_x::Patterns) -> Vec<Pattern> {
    let mut hit_patterns = Vec::new();
    patterns.into_iter().for_each(|m| {
        m.matches().for_each(|n| {
            let r = n.range();
            hit_patterns.push(Pattern::new(
                m.identifier().to_string(),
                r.start,
                r.end - r.start,
                format!("{:?}", n.data()),
            ));
        });
    });
    hit_patterns
}

fn get_metadata_string_field(meta: yara_x::Metadata, field_name: &str) -> Option<String> {
    if !meta.is_empty() {
        for (key, value) in meta.into_iter() {
            if key.to_lowercase() == field_name.to_lowercase() {
                if let yara_x::MetaValue::String(s) = value {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

pub fn count_folders(hits: &[FileHits], base_folders: Vec<String>) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();

    for hit in hits {
        let hit_folders: HashSet<String> = hit.get_bn_folders().into_iter().collect();

        // If base_folders is empty -> always count
        // Otherwise -> only count if all base_folders are present in hit_folders
        if base_folders.is_empty() || base_folders.iter().all(|f| hit_folders.contains(f)) {
            for folder in hit_folders {
                *counts.entry(folder).or_insert(0) += 1;
            }
        }
    }

    counts
}

pub fn build_path_get_next_folder(
    file_hit: &FileHits,
    existing_path: &Vec<String>,
    folder_counts: &HashMap<String, usize>,
) -> Option<String> {
    file_hit
        .get_bn_folders()
        .into_iter()
        .filter(|folder| !existing_path.contains(folder))
        .filter_map(|folder| folder_counts.get(&folder).map(|&count| (folder, count)))
        .max_by(|(f1, c1), (f2, c2)| {
            c1.cmp(c2).then_with(|| f2.cmp(f1)) // tie: alphabetical
        })
        .map(|(folder, _)| folder)
}

pub fn get_all_meta_file_rules(all_hits: &[FileHits]) -> HashMap<String, Vec<MetaRule>> {
    let mut map: HashMap<String, Vec<MetaRule>> = HashMap::new();

    for fh in all_hits {
        map.insert(fh.file_id.clone(), fh.hits.clone());
    }

    map
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scan_bytes(
    ptr: *const u8,
    len: usize,
    folder: *const c_char,
    compiled_rules_file_name: *const c_char,
) -> *const c_char {
    if ptr.is_null() || folder.is_null() || compiled_rules_file_name.is_null() {
        log::error!("A parameter is null\n\n");
        return CString::new("").unwrap().into_raw();
    }

    // Convert C strings to Rust Strings
    let folder_str = match unsafe { CStr::from_ptr(folder).to_str() } {
        Ok(s) => s.to_string(),
        Err(_) => {
            log::error!("folder is none\n\n");
            return CString::new("").unwrap().into_raw();
        }
    };

    let compiled_rules_str = match unsafe { CStr::from_ptr(compiled_rules_file_name).to_str() } {
        Ok(s) => s.to_string(),
        Err(_) => {
            log::error!("compiled rules is none\n\n");
            return CString::new("").unwrap().into_raw();
        }
    };

    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    let rules = Rules::new(compiled_rules_str, folder_str);

    match rules.load() {
        Ok(yrules) => {
            log::info!("Scanning Bytes\n\n");
            let results = Scanner::scan_bytes(yrules, slice);
            CString::new(results).unwrap().into_raw()
        }
        Err(_) => {
            log::error!("Error loading rules");
            CString::new("").unwrap().into_raw()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn scan_rule_against_bytes(
    ptr: *const u8,
    len: usize,
    rule: *const c_char,
) -> *const c_char {
    if ptr.is_null() || rule.is_null() {
        log::error!("A parameter is null\n\n");
        return CString::new("").unwrap().into_raw();
    }

    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

    let rule_str = match unsafe { CStr::from_ptr(rule).to_str() } {
        Ok(s) => s.to_string(),
        Err(e) => {
            log::error!("Error loading rule: {}\n\n", e);
            return CString::new("").unwrap().into_raw();
        }
    };

    let mut compiler = yara_x::Compiler::new();

    let source_code = yara_x::SourceCode::from(rule_str.as_str());

    match compiler.add_source(source_code) {
        Ok(_) => {
            let built_rules = compiler.build();
            log::info!("Scanning Bytes\n\n");
            let results = Scanner::scan_bytes(built_rules, slice);
            CString::new(results).unwrap().into_raw()
        }
        Err(e) => {
            log::error!("Error compiling rule\n{}", e);
            return CString::new("").unwrap().into_raw();
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn module_info(bytes: *const u8, len: usize) -> *const c_char {
    if bytes.is_null() {
        log::error!("bytes parameter is null\n\n");
        return CString::new("").unwrap().into_raw();
    }

    let slice = unsafe { std::slice::from_raw_parts(bytes, len) };

    let results = Scanner::module_info(slice);
    CString::new(results).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn compile(rule: *const c_char) -> *const c_char {
    if rule.is_null() {
        log::error!("Rule parameter is null\n\n");
        return CString::new("").unwrap().into_raw();
    }

    // Convert C strings to Rust Strings
    let rule_str = match unsafe { CStr::from_ptr(rule).to_str() } {
        Ok(s) => s.to_string(),
        Err(e) => {
            log::error!("Error loading rule: {}\n\n", e);
            return CString::new("").unwrap().into_raw();
        }
    };

    let result = Rules::compile(rule_str);
    CString::new(result).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn format(rule: *const c_char) -> *const c_char {
    if rule.is_null() {
        log::error!("Rule parameter is null\n\n");
        return CString::new("").unwrap().into_raw();
    }

    // Convert C strings to Rust Strings
    let rule_str = match unsafe { CStr::from_ptr(rule).to_str() } {
        Ok(s) => s.to_string(),
        Err(e) => {
            log::error!("Error loading rule: {}\n\n", e);
            return CString::new("").unwrap().into_raw();
        }
    };

    let result = Rules::format(rule_str);
    CString::new(result).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free_rust_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        // Take ownership and drop to free memory
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn get_library_versions_json() -> *const c_char {
    // Get compile-time version for yara-x
    let yara_x_version = env!("YARA_X_VERSION");

    // Build the JSON object
    let info = json!({
        "yara-x": yara_x_version,
    });

    // Convert to string and return as *const c_char
    let result = match serde_json::to_string(&info) {
        Ok(json_str) => CString::new(json_str).unwrap(),
        Err(_) => CString::new("{}").unwrap(),
    };

    result.into_raw()
}
