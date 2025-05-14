rm src/bpf/netdig.skel.rs
rm -rf target/debug/build/netdig-* target/debug/netdig
cargo build

# sudo ./target/debug/netdig
