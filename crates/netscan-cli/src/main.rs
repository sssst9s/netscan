mod cli;
mod config;
mod modes;
mod progress;
mod run;

use anyhow::Result;
use clap::Parser;

use cli::Args;

fn main() {
    let args = Args::parse();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("netscan: could not start the async runtime: {err}");
            std::process::exit(1);
        }
    };

    let code = match runtime.block_on(dispatch(&args)) {
        Ok(code) => code,
        Err(err) => {
            report_error(&err);
            1
        }
    };
    std::process::exit(code);
}

async fn dispatch(args: &Args) -> Result<i32> {
    if args.list_interfaces {
        modes::list_interfaces()?;
        return Ok(0);
    }
    if args.list_profiles {
        let resolved = config::resolve_for_listing(args)?;
        modes::list_profiles(&resolved.registry);
        return Ok(0);
    }
    if args.list_probes {
        let resolved = config::resolve_for_listing(args)?;
        modes::list_probes(&resolved.config)?;
        return Ok(0);
    }
    if let Some(paths) = &args.compare {
        return modes::run_compare(paths, args);
    }

    if args.needs_targets() && args.targets.is_empty() {
        anyhow::bail!(
            "no targets given.\n\n               netscan 192.168.1.1            scan one host\n               netscan 192.168.1.0/24         scan a network\n               netscan --local                scan the networks this machine is on\n\n             Run `netscan --help` for the full list of options."
        );
    }

    let resolved = config::resolve(args)?;

    if args.verbosity() == cli::Verbosity::Debug {
        if let Some(path) = &resolved.config_path {
            eprintln!("netscan: configuration from {}", path.display());
        }
    }

    if args.watch.is_some() {
        return modes::run_watch(resolved.config, args).await;
    }

    let report = run::scan(resolved.config, args).await?;
    run::emit(&report, args)?;

    if let Some(path) = &args.inventory {
        let inventory = modes::update_inventory(&report, path)?;
        if args.verbosity() != cli::Verbosity::Quiet {
            eprintln!(
                "netscan: inventory {} now holds {} host(s) and {} service(s)",
                path.display(),
                inventory.len(),
                inventory.service_count()
            );
        }
    }

    Ok(run::exit_code(&report))
}

fn report_error(err: &anyhow::Error) {
    eprintln!("netscan: {err}");
    for cause in err.chain().skip(1) {
        eprintln!("  caused by: {cause}");
    }
}
