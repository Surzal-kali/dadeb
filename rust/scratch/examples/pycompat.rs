//! Cross-compat probe: exercise the SAME scratch.db layout the Python store
//! (`utils/scratch_store.py`) writes and reads, from both directions.
//!
//!   store:    printf '{"k":"v"}' | cargo run --example pycompat -- store <db> <data_dir> <agent_id> <tool_id> <chat_id?>
//!   retrieve: cargo run --example pycompat -- retrieve <db> <data_dir> <agent_id> <scratch_ref>
//!   list:     cargo run --example pycompat -- list <db> <data_dir> <agent_id> [limit]
//!
//! Each mode prints one compact JSON line (the StoreReceipt envelope, the
//! retrieve envelope, or the listing) so the python side can verify a
//! Rust-written entry and vice versa. Use env `SCRATCH_TTL_HOURS` etc. for
//! config — this example deliberately goes through `open_default`-style
//! env handling with explicit paths.

use scratch::{RetrieveOpts, ScratchStore};

fn usage() -> ! {
    eprintln!(
        "usage:\n  \
         pycompat store <db> <data_dir> <agent_id> <tool_id> [chat_id]   (payload JSON on stdin)\n  \
         pycompat retrieve <db> <data_dir> <agent_id> <scratch_ref>\n  \
         pycompat list <db> <data_dir> <agent_id> [limit]"
    );
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("store") if args.len() >= 6 => {
            let mut payload = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut payload).expect("stdin");
            let value: serde_json::Value =
                serde_json::from_str(payload.trim()).expect("stdin is JSON");
            let store = ScratchStore::open(
                std::path::Path::new(&args[2]),
                std::path::Path::new(&args[3]),
                scratch::ScratchConfig::from_env(),
            )
            .expect("open store");
            let receipt = store
                .store(
                    &value,
                    &args[4],
                    &args[5],
                    args.get(6).map(String::as_str),
                )
                .expect("store");
            println!("{}", receipt.to_envelope());
        }
        Some("retrieve") if args.len() >= 6 => {
            let store = ScratchStore::open(
                std::path::Path::new(&args[2]),
                std::path::Path::new(&args[3]),
                scratch::ScratchConfig::from_env(),
            )
            .expect("open store");
            let env = store
                .retrieve(&args[5], &args[4], RetrieveOpts::default())
                .expect("retrieve");
            println!("{env}");
        }
        Some("list") if args.len() >= 5 => {
            let store = ScratchStore::open(
                std::path::Path::new(&args[2]),
                std::path::Path::new(&args[3]),
                scratch::ScratchConfig::from_env(),
            )
            .expect("open store");
            let limit: usize = args
                .get(5)
                .and_then(|l| l.parse().ok())
                .unwrap_or(20);
            let rows = store.list_entries(&args[4], limit).expect("list");
            println!("{}", serde_json::Value::Array(rows));
        }
        _ => usage(),
    }
}