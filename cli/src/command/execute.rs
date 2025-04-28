use clap::Args;
use std::path::PathBuf;
use nexus_vm::{
    elf::ElfFile,
    trace::k_trace,
    error::VMError,
};

#[derive(Debug, Args)]
pub struct ExecuteArgs {
    /// Path to the RISC-V ELF file to execute
    #[arg(name = "elf_path")]
    pub elf_path: PathBuf,
}

pub fn handle_command(args: ExecuteArgs) -> anyhow::Result<()> {
    println!("Loading ELF file: {}", args.elf_path.display());
    
    let elf_file = ElfFile::from_path(&args.elf_path)?;
    
    println!("Executing ELF file...");
    
    match k_trace(elf_file, &[], &[], &[], 1) {
        Ok((view, _trace)) => {
            println!("Execution completed successfully");
            
            // Display exit code
            let exit_code_bytes = view.view_exit_code().unwrap_or_default();
            let exit_code = if !exit_code_bytes.is_empty() {
                exit_code_bytes[0] as u32
            } else {
                println!("Warning: No exit code found");
                0
            };
            
            println!("Exit code: {}", exit_code);
            
            // Display public output if any
            if let Some(output_bytes) = view.view_public_output() {
                if !output_bytes.is_empty() {
                    println!("Public output: {:?}", output_bytes);
                    
                    // Try to print as string if possible
                    if let Ok(output_str) = String::from_utf8(output_bytes.clone()) {
                        if !output_str.trim().is_empty() {
                            println!("Output as string: {}", output_str);
                        }
                    }
                }
            }
            
            // Display debug logs if any
            if let Some(logs) = view.view_debug_logs() {
                if !logs.is_empty() {
                    println!("\nDebug logs:");
                    for (i, log) in logs.iter().enumerate() {
                        if let Ok(log_str) = String::from_utf8(log.clone()) {
                            println!("{}: {}", i, log_str);
                        } else {
                            println!("{}: {:?}", i, log);
                        }
                    }
                }
            }
            
            Ok(())
        }
        Err(VMError::VMExited(code)) => {
            println!("Program exited with code: {}", code);
            Ok(())
        }
        Err(e) => {
            println!("Execution failed: {:?}", e);
            Err(e.into())
        }
    }
} 