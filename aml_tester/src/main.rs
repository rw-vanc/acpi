/*
 * This is a small program that is meant for testing the AML parser on artificial
 * AML. We want to:
 *      - scan a directory for ASL files
 *      - compile them using `iasl` into AML files (these should be gitignored), but only if the ASL file has a
 *        newer timestamp than the AML file (or just compile if there isn't a corresponding AML file)
 *      - Run the AML parser on each AML file, printing test output like `cargo test` does in a nice table for
 *        each AML file
 *      - For failing tests, print out a nice summary of the errors for each file
 */

use aml::{AmlContext, DebugVerbosity, AmlError};
use clap::{Arg, ArgGroup, ArgAction};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{Read, Write},
    ops::Not,
    path::{Path, PathBuf},
    process::Command,
};

enum CompilationOutcome {
    DoesNotExist,
    Ignored,
    IsAml(PathBuf),
    Newer(PathBuf),
    NotCompiled(PathBuf),
    Failed(PathBuf),
    Succeeded(PathBuf),
}

fn main() -> std::io::Result<()> {
    log::set_logger(&Logger).unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    let matches = clap::Command::new("aml_tester")
        .version("v0.1.0")
        .author("Isaac Woods")
        .about("Compiles and tests ASL files")
        .arg(Arg::new("no_compile").long("no-compile").action(ArgAction::SetTrue).help("Don't compile asl to aml"))
        .arg(Arg::new("reset").long("reset").action(ArgAction::SetTrue).help("Clear namespace after each file"))
        .arg(Arg::new("path").short('p').long("path").required(false).action(ArgAction::Set).value_name("DIR"))
        .arg(Arg::new("files").action(ArgAction::Append).value_name("FILE.{asl,aml}"))
        .group(ArgGroup::new("files_list").args(["path", "files"]).required(true))
        .get_matches();

    let files: Vec<String> = if matches.contains_id("path") {
        let dir_path = Path::new(matches.get_one::<String>("path").unwrap());
        println!("Running tests in directory: {:?}", dir_path);
        fs::read_dir(dir_path)?.filter_map(| entry | if entry.is_ok() {
            Some(entry.unwrap().path().to_string_lossy().to_string())
        } else {
            None
        }).collect()
    } else {
        matches.get_many::<String>("files").unwrap_or_default().map(| f | f.to_string()).collect()
    };

    if !files.iter().fold(true, | had_failure, file | {
        if Path::new(file).is_file() {
            had_failure
        } else {
            println!("File not found: {}", file);
            false
        }
    }) {
        return Ok(());
    }

    let user_wants_compile = !matches.get_flag("no_compile");
    let can_compile = if !user_wants_compile {
        false
    } else {
        // Test if `iasl` is installed, so we can give a good error later if it's not
        match Command::new("iasl").arg("-v").status() {
            Ok(exit_status) if exit_status.success() => true,
            Ok(exit_status) => {
                panic!("`iasl` exited with unsuccessfull status: {:?}", exit_status);
            },
            Err(_) => false,
        }
    };

    let compiled_files: Vec<CompilationOutcome> = files.iter().map(| file | resolve_and_compile(file, can_compile).unwrap()).collect();

    // check compilation should have happened but did not
    if user_wants_compile && compiled_files.iter().any(| outcome | matches!(outcome, CompilationOutcome::NotCompiled(_))) {
        panic!("`iasl` is not installed, but we want to compile some ASL files! Pass --no-compile, or install `iasl`")
    }
    if user_wants_compile {
        let (passed, failed) = compiled_files.iter()
            .fold((0, 0), | (passed, failed), outcome | match outcome {
                CompilationOutcome::Succeeded(_) => (passed + 1, failed),
                CompilationOutcome::Failed(_) => (passed, failed + 1),
                _ => (passed, failed),
            });
        if passed + failed > 0 {
            println!("Compiled {} ASL files: {} passed, {} failed.", passed + failed, passed, failed);
        }
    }

    let aml_files = compiled_files.iter().filter_map(| outcome | match outcome {
        CompilationOutcome::IsAml(path) => Some(path),
        CompilationOutcome::Newer(path) => Some(path),
        CompilationOutcome::Succeeded(path) => Some(path),
        _ => None,
    });

    let reset_context = matches.get_flag("reset");
    let mut context = AmlContext::new(Box::new(Handler), DebugVerbosity::None);

    let (passed, failed) = aml_files.fold((0, 0), |(passed, failed), file_entry| {
        print!("Testing AML file: {:?}... ", file_entry);
        std::io::stdout().flush().unwrap();

        let mut file = File::open(file_entry).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();

        const AML_TABLE_HEADER_LENGTH: usize = 36;
        
        if reset_context {
            context = AmlContext::new(Box::new(Handler), DebugVerbosity::None);
        }

        match context.parse_table(&contents[AML_TABLE_HEADER_LENGTH..]) {
            Ok(()) => {
                println!("{}OK{}", termion::color::Fg(termion::color::Green), termion::style::Reset);
                println!("Namespace: {:#?}", context.namespace);
                (passed + 1, failed)
            }

            Err(err) => {
                println!("{}Failed ({:?}){}", termion::color::Fg(termion::color::Red), err, termion::style::Reset);
                println!("Namespace: {:#?}", context.namespace);
                (passed, failed + 1)
            }
        }
    });

    println!("Test results: {} passed, {} failed", passed, failed);
    Ok(())
}

/// Determine what to do with this file - ignore, compile and parse, or just parse.
/// If ".aml" does not exist, or if ".asl" is newer, compiles the file.
/// If the ".aml" file is newer, or if the original file is not ".asl",
/// indicate it is ready to parse. Assumes the file exists.
fn resolve_and_compile(name: &str, can_compile: bool) -> std::io::Result<CompilationOutcome> {
    let path = PathBuf::from(name);

    // If this file is aml and it exists, it's ready for parsing
    // metadata() will error if the file does not exist
    if path.extension() == Some(OsStr::new("aml")) && path.metadata()?.is_file() {
        return Ok(CompilationOutcome::IsAml(path));
    }

    // If this file is not asl, it's not interesting. Error if the file does not exist.
    if path.extension() != Some(OsStr::new("asl")) || !path.metadata()?.is_file() {
        return Ok(CompilationOutcome::Ignored);
    }

    if !can_compile {
        return Ok(CompilationOutcome::NotCompiled(path));
    }
    
    let aml_path = path.with_extension("aml");

    if aml_path.is_file() {
        let asl_last_modified = path.metadata()?.modified()?;
        let aml_last_modified = aml_path.metadata()?.modified()?;
        // If the aml is more recent than the asl, use the existing aml
        // Otherwise continue to compilation
        if asl_last_modified <= aml_last_modified {
            return Ok(CompilationOutcome::Newer(aml_path))
        }
    }

    // Compile the ASL file using `iasl`
    println!("Compiling file: {}", name);
    let output = Command::new("iasl").arg(name).output()?;

    if !output.status.success() {
        println!(
            "Failed to compile ASL file: {}. Output from iasl:\n {}",
            name,
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(CompilationOutcome::Failed(path))
    } else {
        Ok(CompilationOutcome::Succeeded(aml_path))
    }
}

struct Logger;

impl log::Log for Logger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        println!("[{}] {}", record.level(), record.args());
    }

    fn flush(&self) {
        std::io::stdout().flush().unwrap();
    }
}

struct Handler;

impl aml::Handler for Handler {
    fn read_u8(&self, _address: usize) -> u8 {
        unimplemented!()
    }
    fn read_u16(&self, _address: usize) -> u16 {
        unimplemented!()
    }
    fn read_u32(&self, _address: usize) -> u32 {
        unimplemented!()
    }
    fn read_u64(&self, _address: usize) -> u64 {
        unimplemented!()
    }

    fn write_u8(&mut self, _address: usize, _value: u8) {
        unimplemented!()
    }
    fn write_u16(&mut self, _address: usize, _value: u16) {
        unimplemented!()
    }
    fn write_u32(&mut self, _address: usize, _value: u32) {
        unimplemented!()
    }
    fn write_u64(&mut self, _address: usize, _value: u64) {
        unimplemented!()
    }

    fn read_io_u8(&self, _port: u16) -> u8 {
        unimplemented!()
    }
    fn read_io_u16(&self, _port: u16) -> u16 {
        unimplemented!()
    }
    fn read_io_u32(&self, _port: u16) -> u32 {
        unimplemented!()
    }

    fn write_io_u8(&self, _port: u16, _value: u8) {
        unimplemented!()
    }
    fn write_io_u16(&self, _port: u16, _value: u16) {
        unimplemented!()
    }
    fn write_io_u32(&self, _port: u16, _value: u32) {
        unimplemented!()
    }

    fn read_pci_u8(&self, _segment: u16, _bus: u8, _device: u8, _function: u8, _offset: u16) -> u8 {
        unimplemented!()
    }
    fn read_pci_u16(&self, _segment: u16, _bus: u8, _device: u8, _function: u8, _offset: u16) -> u16 {
        unimplemented!()
    }
    fn read_pci_u32(&self, _segment: u16, _bus: u8, _device: u8, _function: u8, _offset: u16) -> u32 {
        unimplemented!()
    }
    fn write_pci_u8(&self, _segment: u16, _bus: u8, _device: u8, _function: u8, _offset: u16, _value: u8) {
        unimplemented!()
    }
    fn write_pci_u16(&self, _segment: u16, _bus: u8, _device: u8, _function: u8, _offset: u16, _value: u16) {
        unimplemented!()
    }
    fn write_pci_u32(&self, _segment: u16, _bus: u8, _device: u8, _function: u8, _offset: u16, _value: u32) {
        unimplemented!()
    }
}
