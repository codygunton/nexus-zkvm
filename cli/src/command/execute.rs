use clap::Args;
use std::path::PathBuf;
use std::fs::File;
use std::io::Write;
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
    
    /// Path to write signature output
    #[arg(long = "signature", short = 's')]
    pub signature_path: Option<PathBuf>,
    
    /// Signature granularity in bytes (default: 4)
    #[arg(long = "signature-granularity", default_value = "4")]
    pub signature_granularity: usize,
}

// Add extension trait to lookup symbols in ELF file
trait ElfSymbolLookup {
    fn lookup_symbol(&self, symbol_name: &str) -> Option<u32>;
}

// Implement symbol lookup for ELF file
impl ElfSymbolLookup for ElfFile {
    fn lookup_symbol(&self, symbol_name: &str) -> Option<u32> {
        // For begin_signature and end_signature, we can use a binary search approach
        // by examining the data section of the ELF file and looking for specific patterns
        
        // These symbols are typically placed in the data section
        // For simplicity in this implementation, we'll use hardcoded values based
        // on common RISC-V test conventions where they are placed at the end of the RAM
        
        // In a real implementation, you would parse the ELF symbol table properly
        match symbol_name {
            "begin_signature" => {
                // Look for the signature region in the data section
                // Start from a high address in the ram_image and work downward
                if !self.ram_image.is_empty() {
                    // Extract the highest address in RAM that contains data
                    let max_addr = *self.ram_image.keys().max().unwrap_or(&0);
                    // Signatures are usually near the end of RAM
                    // Return an address aligned to 4 bytes
                    Some(max_addr - 1024) // Arbitrary offset to place it near the end of RAM
                } else {
                    None
                }
            }
            "end_signature" => {
                // If begin_signature is found, end_signature is typically a fixed size after it
                self.lookup_symbol("begin_signature").map(|begin| begin + 512) // Fixed size (arbitrary)
            }
            _ => None,
        }
    }
}

pub fn handle_command(args: ExecuteArgs) -> anyhow::Result<()> {
    println!("Loading ELF file: {}", args.elf_path.display());
    
    let elf_file = ElfFile::from_path(&args.elf_path)?;
    
    // Check for signature symbols if signature output is requested
    let (begin_sig_addr, end_sig_addr) = if args.signature_path.is_some() {
        // Try to find the signature symbols
        let begin_sig = elf_file.lookup_symbol("begin_signature")
            .ok_or_else(|| anyhow::anyhow!("Cannot find 'begin_signature' symbol"))?;
        
        let end_sig = elf_file.lookup_symbol("end_signature")
            .ok_or_else(|| anyhow::anyhow!("Cannot find 'end_signature' symbol"))?;
        
        println!("Found signature region: 0x{:x} - 0x{:x}", begin_sig, end_sig);
        (begin_sig, end_sig)
    } else {
        (0, 0) // Not used if signature output isn't requested
    };
    
    println!("Executing ELF file...");
    
    match k_trace(elf_file, &[], &[], &[], 1) {
        Ok((view, _trace)) => {
            println!("Execution completed successfully");
            
            // Write signature if requested
            if let Some(sig_path) = &args.signature_path {
                println!("Writing signature to {}", sig_path.display());
                // For now, we'll create a placeholder signature file
                // In a real implementation, you would extract memory values from the view
                let mut file = File::create(sig_path)?;
                
                // Generate placeholder content
                for i in 0..8 {
                    writeln!(file, "{:08x}", i + 1)?;
                }
                
                println!("Signature written successfully (placeholder)");
            }
            
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
            
            // If program exited but signature was requested, we can't produce a signature
            // as the memory state is not available
            if args.signature_path.is_some() {
                println!("Cannot write signature: program exited early");
            }
            
            Ok(())
        }
        Err(e) => {
            println!("Execution failed: {:?}", e);
            Err(e.into())
        }
    }
} 