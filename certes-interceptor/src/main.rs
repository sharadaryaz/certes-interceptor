use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    
    // Initialize host logging (Standard Output)
    env_logger::init();

    // 1. Load the eBPF bytecode
    // We point to the specific cross-compiled BPF artifact
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/certes-interceptor"
    ))?;

    // 2. Initialize Kernel Logging (aya-log)
    // This allows info! and debug! macros in the EBPF code to show up here
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // 3. Prepare the Interface
    // 'clsact' is the required queueing discipline for TC eBPF programs
    let _ = tc::qdisc_add_clsact(&opt.iface);
    info!("Initialized clsact on interface: {}", opt.iface);

    // 4. Attach Ingress (Redirect: 80 -> 8080)
    let ingress_prog: &mut SchedClassifier = bpf.program_mut("certes_ingress")
        .expect("Program 'certes_ingress' not found")
        .try_into()?;
    ingress_prog.load()?;
    ingress_prog.attach(&opt.iface, TcAttachType::Ingress)?;
    info!("Attached Ingress Hook (80 -> 8080)");

    // 5. Attach Egress (Reverse: 8080 -> 80)
    let egress_prog: &mut SchedClassifier = bpf.program_mut("certes_egress")
        .expect("Program 'certes_egress' not found")
        .try_into()?;
    egress_prog.load()?;
    egress_prog.attach(&opt.iface, TcAttachType::Egress)?;
    info!("Attached Egress Hook (8080 -> 80)");

    info!("Interceptor active. Press Ctrl-C to terminate and detach hooks.");

    // 6. Graceful Shutdown
    signal::ctrl_c().await?;
    info!("Ctrl-C received. Detaching programs and exiting...");

    Ok(())
}