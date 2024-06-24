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

use aml::{AmlContext, DebugVerbosity};
use clap::{Arg, ArgAction, ArgGroup};
use std::{
    collections::HashSet, convert::TryInto, ffi::OsStr, fs::{self, File}, io::{Read, Write}, path::{Path, PathBuf}, process::Command
};
// use toml::Table;
use toml::value::Array;
use serde::{Deserialize, Serialize};
// use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;

enum CompilationOutcome {
    Ignored,
    IsAml(PathBuf),
    Newer(PathBuf),
    NotCompiled(PathBuf),
    Failed(PathBuf),
    Succeeded(PathBuf),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct TestSet {
    default_tests: Default,
    acpi: Acpi,
    sequences: Vec<Sequence>,
    test: Vec<Test>
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(untagged)]
enum Action{
    MemOp {mem_op: String, address: usize, value: u64},
    PciOp {pci_op: String, segment: u16, bus: u8, device: u8, function: u8, value: u64},
    IoOp {io_op: String, port: u16, value: u64}
}

 #[derive(Deserialize, Serialize, Clone, Debug)]
 struct Default {
    tests: Vec<String>,
 }

 #[derive(Deserialize, Serialize, Clone, Debug)]
 struct Acpi {
    files: Vec<String>,
    init: String
 }

 #[derive(Deserialize, Serialize, Clone, Debug)]
struct Sequence {
    name: String,
    // pre_state: Array,
    // expect: Array,
    actions: Vec<Action>,
    action: Option<String>,
    p1: Option<u32>
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct Test {
    name: String,
    sequence: Array
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
        .arg(Arg::new("toml").short('t').long("toml").required(false).action(ArgAction::Set).value_name("TOML"))
        .group(ArgGroup::new("files_list").args(["path", "files", "toml"]).required(true))
        .get_matches();



    // Get an initial list of files - may not work correctly on non-UTF8 OsString
    let mut real2: Option<TestSet> = None;
    let files: Vec<String> = if matches.contains_id("path") {
        let dir_path = Path::new(matches.get_one::<String>("path").unwrap());
        println!("Running tests in directory: {:?}", dir_path);
        fs::read_dir(dir_path)?
            .filter_map(|entry| {
                if entry.is_ok() {
                    Some(entry.unwrap().path().to_string_lossy().to_string())
                } else {
                    None
                }
            })
            .collect()
    } else if matches.contains_id("files"){
        matches.get_many::<String>("files").unwrap_or_default().map(|name| name.to_string()).collect()
    } else {
        let dir_path: &Path = Path::new(matches.get_one::<String>("toml").unwrap());
        let contents = fs::read_to_string(dir_path);
        let real = toml::from_str(&contents.unwrap());
        real2 = real.unwrap();
        let files = real2.clone().unwrap().acpi.files.clone();
        files.into_iter().collect()

        // real2.unwrap().acpi.files.into_iter().collect()
    };

    // Make sure all files exist, propagate error if it occurs
    files.iter().fold(Ok(()), |result: std::io::Result<()>, file| {
        let path = Path::new(file);
        if !path.is_file() {
            println!("Not a regular file: {}", file);
            // Get the io error if there is one
            path.metadata()?;
        }
        result
    })?;

    // Make sure we have the ability to compile ASL -> AML, if user wants it
    let user_wants_compile = !matches.get_flag("no_compile");
    let can_compile = user_wants_compile &&
        // Test if `iasl` is installed, so we can give a good error later if it's not
        match Command::new("iasl").arg("-v").status() {
            Ok(exit_status) if exit_status.success() => true,
            Ok(exit_status) => {
                panic!("`iasl` exited with unsuccessful status: {:?}", exit_status);
            },
            Err(_) => false,
    };

    let compiled_files: Vec<CompilationOutcome> =
        files.iter().map(|name| resolve_and_compile(name, can_compile).unwrap()).collect();

    // Check if compilation should have happened but did not
    if user_wants_compile
        && compiled_files.iter().any(|outcome| matches!(outcome, CompilationOutcome::NotCompiled(_)))
    {
        panic!(
            "`iasl` is not installed, but we want to compile some ASL files! Pass --no-compile, or install `iasl`"
        );
    }
    // Report compilation results
    if user_wants_compile {
        let (passed, failed) = compiled_files.iter().fold((0, 0), |(passed, failed), outcome| match outcome {
            CompilationOutcome::Succeeded(_) => (passed + 1, failed),
            CompilationOutcome::Failed(_) => (passed, failed + 1),
            _ => (passed, failed),
        });
        if passed + failed > 0 {
            println!("Compiled {} ASL files: {} passed, {} failed.", passed + failed, passed, failed);
            println!();
        }
    }

    // Make a list of the files we have processed, and skip them if we see them again
    let mut dedup_list: HashSet<PathBuf> = HashSet::new();

    // Filter down to the final list of AML files
    let aml_files = compiled_files
        .iter()
        .filter_map(|outcome| match outcome {
            CompilationOutcome::IsAml(path) => Some(path.clone()),
            CompilationOutcome::Newer(path) => Some(path.clone()),
            CompilationOutcome::Succeeded(path) => Some(path.clone()),
            CompilationOutcome::Ignored | CompilationOutcome::Failed(_) | CompilationOutcome::NotCompiled(_) => {
                None
            }
        })
        .filter(|path| {
            if dedup_list.contains(path) {
                false
            } else {
                dedup_list.insert(path.clone());
                true
            }
        });

    let user_wants_reset = matches.get_flag("reset");
    // let sequence1 = vec!["read_pci_32, segment = 0, bus = 0, device = 0, function = 0, value = 0", "read_u8, addr=0x6fe7b0c0, value = 0"];
    // let sequence2 = real2.clone().unwrap().sequences[0].actions.clone();
    // let pos : Option<Position>;
    // let position: Position =  {Position{sequence: &real2.unwrap().sequence[0], count: AtomicUsize::new(0)}};
    // pos = Some(position);
    // let handler = Arc::new(Handler{handler_inner: HandlerInner{test_set: real2, position: None}});
    let handler_inner = Arc::new(HandlerInner { test_set: real2, position: Mutex::new(None) });
    let handler = Handler{handler_inner: handler_inner.clone()};
    // Arc::try_unwrap(handler);
    handler_inner.set_position("initialize".to_string());

    let mut context = AmlContext::new(Box::new(handler), DebugVerbosity::None);
    

    let (passed, failed) = aml_files.fold((0, 0), |(passed, failed), file_entry| {
        print!("Testing AML file: {:?}... ", file_entry);
        std::io::stdout().flush().unwrap();

        let mut file = File::open(file_entry).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();

        const AML_TABLE_HEADER_LENGTH: usize = 36;

        if user_wants_reset {
            context = AmlContext::new(Box::new(Handler{ handler_inner: Arc::new(HandlerInner{test_set: None, position: Mutex::new(None)})}), DebugVerbosity::None);
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
    let handler_error: bool = handler_inner.position.lock().unwrap().as_ref().unwrap().err;
    if handler_error {
        println!("initialize failed");
    } else {
        println!("initialize succeeded");
    }
    Ok(())
}

/// Determine what to do with this file - ignore, compile and parse, or just parse.
/// If ".aml" does not exist, or if ".asl" is newer, compiles the file.
/// If the ".aml" file is newer, indicate it is ready to parse.
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

    let aml_path = path.with_extension("aml");

    if aml_path.is_file() {
        let asl_last_modified = path.metadata()?.modified()?;
        let aml_last_modified = aml_path.metadata()?.modified()?;
        // If the aml is more recent than the asl, use the existing aml
        // Otherwise continue to compilation
        if asl_last_modified <= aml_last_modified {
            return Ok(CompilationOutcome::Newer(aml_path));
        }
    }

    if !can_compile {
        return Ok(CompilationOutcome::NotCompiled(path));
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

struct Handler {
    handler_inner: Arc<HandlerInner>
    // iter:dyn Iterator<Item=String>,
}

impl Handler {
    fn handle_read_action(&self, action: Action) -> Option<u64>{
        return self.handler_inner.handle_read_action(action);
    }

    fn handle_write_action(&self, action: Action) -> Option<Action>{
        return self.handler_inner.handle_write_action(action);
    }
}

#[derive(Debug)]
struct HandlerInner {
    test_set: Option<TestSet>,
    position: Mutex<Option<Position>>,
    // next: Option<&'a str>
}

impl HandlerInner {

    fn set_position(&self, name: String) {
        println!("this is being called position");
        let length = self.test_set.as_ref().unwrap().sequences.len();
        let sequences = self.test_set.as_ref().unwrap().sequences.clone();
        for i in 0..length { // we want to change this completely, start with range 0..sequences.len check the name, return the index with the right name
            if sequences[i].name == name {
                let position = Position { sequence: i, sequence_position: 0, err: false };
                *self.position.lock().unwrap() = Some(position);
                // self.handler_inner = Some(HandlerInner{sequence: i, sequence_position: AtomicUsize::new(0)});
            }
        }
    }

    fn handle_read_action(&self, action: Action) -> Option<u64>{
        // let current_pos = self.position.lock().unwrap().as_ref().unwrap().sequence_position;
        // println!("the current position is {current_pos}");
        // println!("{self.position.sequence}")
        if self.position.lock().unwrap().as_ref().unwrap().err == true {
            return None;
        }
        let current_action = self.position.lock().unwrap().as_mut().unwrap().get_next(self.test_set.as_ref().unwrap().sequences.as_ref());
        if current_action.is_none() {
            return None;
        }
        let matches: Option<u64> = match (current_action.unwrap(), action) {
            (Action::IoOp { io_op: a_io_op, port: a_io_port, value: a_io_value }, Action::IoOp { io_op: b_io_op, port: b_io_port, value: _b_io_value }) => {
                if a_io_op == b_io_op && a_io_port == b_io_port { Some(a_io_value)} else { 
                    self.position.lock().unwrap().as_mut().unwrap().set_err(true);
                    println!("a io is {} and b io is {}", a_io_op, b_io_op);
                    None 
                }
            },
            (Action::PciOp { pci_op: a_pci_op, segment: a_segment, bus: a_bus, device: a_device, function: a_function, value: a_value }, Action::PciOp { pci_op: b_pci_op, segment: b_segment, bus: b_bus, device: b_device, function: b_function, value: b_value })=> {
                if a_pci_op == b_pci_op && a_segment == b_segment && a_bus == b_bus && a_device == b_device && a_function == b_function {Some(a_value)} else {
                    self.position.lock().unwrap().as_mut().unwrap().set_err(true); 
                    println!("a pci is {} and b pci is {}", a_pci_op, b_pci_op);
                    None
                }
            },
            (Action::MemOp { mem_op: a_mem_op, address: a_address, value: a_value }, Action::MemOp { mem_op: b_mem_op, address: b_address, value: _b_value }) => {
                if a_mem_op == b_mem_op && a_address == b_address {Some(a_value)} else {
                    self.position.lock().unwrap().as_mut().unwrap().set_err(true);
                    println!("a io is {} and b io is {}", a_mem_op, b_mem_op);
                    None
                }
            },
            _ => None

        };
        // let printval = matches.unwrap_or(800);
        // println!("the value of matches is {printval}");
        return matches;

    }

    fn handle_write_action(&self, action: Action) -> Option<Action>{
        let current_pos = self.position.lock().unwrap().is_some();
        println!("the current position is {current_pos}");
        // println!("{self.position.sequence}")
        self.position.lock().unwrap().as_mut().unwrap().get_next(self.test_set.as_ref().unwrap().sequences.as_ref())

    }

}

#[derive(Debug)]
struct Position {
    sequence: usize,
    sequence_position: usize,
    err: bool,
}

impl Position{
    fn get_next(&mut self, sequences: &Vec<Sequence>) -> Option<Action> {
        if self.sequence_position >= sequences[self.sequence].actions.len(){
            // let len = sequences[self.sequence].actions.len();
            // println!("length is {len}");
            // let len = self.sequence.actions.len();
            // println!("length is : {len}");
            self.err = true;
            return None;
        } else {
            // println!("position get next else is being reached");
            let value = Some(sequences[self.sequence].actions[self.sequence_position].clone());
            self.sequence_position += 1;
            return value;
        }
    }
    fn set_err(&mut self, err: bool) {
        self.err = err;
    }

}

impl aml::Handler for Handler {
    fn read_u8(&self, address: usize) -> u8 {
        println!("read_u8 {address:#x}");
        // let binding = self.position.as_ref().unwrap();
        // let count = binding.count.load(Ordering::Relaxed);
        // println!("count is : {count}");
        // let kind = "read_u8";
        let action = Action::MemOp { mem_op: "read_u8".to_string(), address: address, value: 0 };
        self.handle_read_action(action).unwrap_or(0).try_into().unwrap_or(0)
    }
    fn read_u16(&self, address: usize) -> u16 {
        println!("read_u16 {address:#x}");
        // let binding = self.position.as_ref().unwrap();
        // let count = binding.count.load(Ordering::Relaxed);
        // println!("count is : {count}");
        // let kind = "read_u16";
        let action = Action::MemOp { mem_op: "read_u16".to_string(), address: address, value: 0 };
        self.handle_read_action(action).unwrap_or(0).try_into().unwrap_or(0)
    }
    fn read_u32(&self, address: usize) -> u32 {
        println!("read_u32 {address:#x}");
        // let binding = self.position.as_ref().unwrap();
        // let count = binding.count.load(Ordering::Relaxed);
        // println!("count is : {count}");
        // let current = self.get_next().unwrap();
        // let kind = "read_u32";
        let action = Action::MemOp { mem_op: "read_u32".to_string(), address: address, value: 0 };
        self.handle_read_action(action).unwrap_or(0).try_into().unwrap_or(0)
    }
    fn read_u64(&self, address: usize) -> u64 {
        println!("read_u64 {address:#x}");
        // let binding = self.position.as_ref().unwrap();
        // let count = binding.count.load(Ordering::Relaxed);
        // println!("count is : {count}");
        // let current = self.get_next().unwrap();
        // let kind = "read_u64";
        let action = Action::MemOp { mem_op: "read_u64".to_string(), address: address, value: 0 };
        self.handle_read_action(action).unwrap_or(0)
    }

    fn write_u8(&mut self, address: usize, value: u8) {
        println!("write_u8 {address:#x}<-{value:#x}");
    }
    fn write_u16(&mut self, address: usize, value: u16) {
        println!("write_u16 {address:#x}<-{value:#x}");
    }
    fn write_u32(&mut self, address: usize, value: u32) {
        println!("write_u32 {address:#x}<-{value:#x}");
    }
    fn write_u64(&mut self, address: usize, value: u64) {
        println!("write_u64 {address:#x}<-{value:#x}");
    }

    fn read_io_u8(&self, port: u16) -> u8 {
        println!("read_io_u8 {port:#x}");
        // let binding = self.position.as_ref().unwrap();
        // let count = binding.count.load(Ordering::Relaxed);
        // println!("count is : {count}");
        // let current = self.get_next().unwrap();
        // let kind = "read_io_u8";
        let action = Action::IoOp { io_op: "read_io_u8".to_string(), port: port, value: 0 };
        self.handle_read_action(action).unwrap_or(0).try_into().unwrap_or(0)
    }
    fn read_io_u16(&self, port: u16) -> u16 {
        println!("read_io_u16 {port:#x}");
        // let binding = self.position.as_ref().unwrap();
        // let count = binding.count.load(Ordering::Relaxed);
        // println!("count is : {count}");
        // let current = self.get_next().unwrap();
        // let kind = "read_io_u16";
        let action = Action::IoOp { io_op: "read_io_u16".to_string(), port: port, value: 0 };
        self.handle_read_action(action).unwrap_or(0).try_into().unwrap_or(0)
    }
    fn read_io_u32(&self, port: u16) -> u32 {
        println!("read_io_u32 {port:#x}");
        // let binding = self.position.as_ref().unwrap();
        // let count = binding.count.load(Ordering::Relaxed);
        // println!("count is : {count}");
        // let current = self.get_next().unwrap();
        // let kind = "read_io_u32";
        let action = Action::IoOp { io_op: "read_io_u32".to_string(), port: port, value: 0 };
        self.handle_read_action(action).unwrap_or(0).try_into().unwrap_or(0)
    }

    fn write_io_u8(&self, port: u16, value: u8) {
        println!("write_io_u8 {port:#x}<-{value:#x}");
    }
    fn write_io_u16(&self, port: u16, value: u16) {
        println!("write_io_u16 {port:#x}<-{value:#x}");
    }
    fn write_io_u32(&self, port: u16, value: u32) {
        println!("write_io_u32 {port:#x}<-{value:#x}");
    }

    fn read_pci_u8(&self, segment: u16, bus: u8, device: u8, function: u8, _offset: u16) -> u8 {
        println!("read_pci_u8 ({segment:#x}, {bus:#x}, {device:#x}, {function:#x})");
        // let binding = self.position.as_ref().unwrap();
        // let count = binding.count.load(Ordering::Relaxed);
        // println!("count is : {count}");
        // let current = self.get_next().unwrap();
        // let kind = "read_pci_u8";
        let action = Action::PciOp { pci_op: "read_pci_u8".to_string(), segment, bus: bus, device: device, function: function, value: 0 };
        self.handle_read_action(action).unwrap_or(0).try_into().unwrap_or(0)
    }
    fn read_pci_u16(&self, segment: u16, bus: u8, device: u8, function: u8, _offset: u16) -> u16 {
        println!("read_pci_u16 ({segment:#x}, {bus:#x}, {device:#x}, {function:#x})");
        // let binding = self.position.as_ref().unwrap();
        // let count = binding.count.load(Ordering::Relaxed);
        // println!("count is : {count}");
        // let current = self.get_next().unwrap();
        // let kind = "read_pci_u16";
        let action = Action::PciOp { pci_op: "read_pci_u16".to_string(), segment, bus: bus, device: device, function: function, value: 0 };
        self.handle_read_action(action).unwrap_or(0).try_into().unwrap_or(0)
    }
    fn read_pci_u32(&self, segment: u16, bus: u8, device: u8, function: u8, _offset: u16) -> u32 {
        println!("read_pci_32 ({segment:#x}, {bus:#x}, {device:#x}, {function:#x})");
        // let binding = self.position.as_ref().unwrap();
        // let count = binding.count.load(Ordering::Relaxed);
        // println!("count is : {count}");
        // let current = self.get_next().unwrap();
        // let kind = "read_pci_u32";
        let action = Action::PciOp { pci_op: "read_pci_u32".to_string(), segment, bus: bus, device: device, function: function, value: 0 };
        self.handle_read_action(action).unwrap_or(0).try_into().unwrap_or(0)
    }

    fn write_pci_u8(&self, segment: u16, bus: u8, device: u8, function: u8, _offset: u16, value: u8) {
        println!("write_pci_u8 ({segment:#x}, {bus:#x}, {device:#x}, {function:#x})<-{value:#x}");
    }
    fn write_pci_u16(&self, segment: u16, bus: u8, device: u8, function: u8, _offset: u16, value: u16) {
        println!("write_pci_u16 ({segment:#x}, {bus:#x}, {device:#x}, {function:#x})<-{value:#x}");
    }
    fn write_pci_u32(&self, segment: u16, bus: u8, device: u8, function: u8, _offset: u16, value: u32) {
        println!("write_pci_u32 ({segment:#x}, {bus:#x}, {device:#x}, {function:#x})<-{value:#x}");
    }

    fn stall(&self, microseconds: u64) {
        println!("Stalling for {}us", microseconds);
    }
    fn sleep(&self, milliseconds: u64) {
        println!("Sleeping for {}ms", milliseconds);
    }
}
