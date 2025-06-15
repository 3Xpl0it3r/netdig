rm src/bpf/*.skel.rs
rm -rf target/debug/build/netdig* target/debug/netdig
# rm -rf target
cargo build 
sudo ./target/debug/netdig --http
