use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::sync::LazyLock;

use bollard::Docker;
use tokio::runtime::Runtime;

// Some constants about cri paths
const _DEFAULT_CRI_RUNTIME_ENDPOINTS: [&'static str; 3] = [
    "unix:///run/containerd/containerd.sock",
    "unix:///run/crio/crio.sock",
    "unix:///var/run/cri-dockerd.sock",
];
const _DEFAULT_DOCKER_ENDPOINT: &'static str = "unix:///var/run/docker.sock";

// Store the id of network namespace <-> container name mapping
static CONTAINER_NETNS_CACHE: LazyLock<HashMap<u64, String>> =
    LazyLock::new(|| init_container_ns());
// 解析docker 容器的元数据, 分别获取docker容器的netns 和对应的docker 容器的名称,
// 将他们存储到hashmap里面
fn init_container_ns() -> HashMap<u64, String> {
    let mut ns_cache = HashMap::<u64, String>::new();

    /* ns_cache.insert(0, "root_ns".to_owned()); */
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        let docker = Docker::connect_with_local_defaults().unwrap();
        let containers: Vec<String> = docker
            .list_containers::<String>(None)
            .await
            .unwrap()
            .iter()
            .filter_map(|c| {
                c.state.as_ref().map(|sts| {
                    if sts.eq("running") == true {
                        c.id.as_ref().cloned()
                    } else {
                        None
                    }
                })
            })
            .map(|c| c.unwrap())
            .collect();

        for c in containers.iter() {
            let cs = docker.inspect_container(c, None).await.unwrap();
            let name = cs.name.clone().unwrap();
            let sanboxkey = cs
                .network_settings
                .as_ref()
                .unwrap()
                .sandbox_key
                .as_ref()
                .unwrap()
                .to_owned();
            // 获取sandboxkey 路径对应的inode号, 这个inode号就对应着这个容器的netns id
            let ns_id = fs::metadata(sanboxkey.as_str()).unwrap().ino();
            ns_cache.insert(ns_id, name);
        }
    });
    ns_cache
}

pub fn get_container_name_by_nsid(nsid: &u64) -> String {
    match CONTAINER_NETNS_CACHE.get(nsid) {
        Some(ctn_name) => ctn_name.to_string(),
        None => format!("{}", nsid),
    }
}
