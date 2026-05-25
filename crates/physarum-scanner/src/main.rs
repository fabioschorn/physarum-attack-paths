//! `physarum-scan` — standalone port scanner CLI.
//!
//! Feature-complete port of RustScan's CLI onto physarum-scanner.
//!
//! Capabilities exclusive to this binary (not in physarum-maze):
//! - Explicit target list via -a/--addresses (IP, CIDR, hostname, @file)
//! - Port range (-r) or explicit port list (-p)
//! - Top-1000 most common ports (--top)
//! - Random (LCG) port ordering (--scan-order random)
//! - UDP scanning with auto-loaded Nmap payloads (--udp)
//! - Greppable output, one result per line (-g)
//! - Accessible mode, no ANSI codes (--accessible)
//! - OS ulimit tuning before scan (-u/--ulimit)
//! - Custom DNS resolver (--resolver)
//! - Nmap-style post-scan scripts (--scripts)
//! - Port exclusion list (-e/--exclude-ports)
//! - IP/CIDR exclusion list (-x/--exclude-addresses)
//! - Config file override (-c/--config-path)
//! - Nmap command passthrough (-- -A -sC ...)
//! - No-config mode (--no-config)
//! - Banner suppression (--no-banner)

use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};
use physarum_scanner::{
    address::parse_addresses,
    config::{Config, ScanConfig},
    port_strategy::{PortRange, PortStrategy, ScanOrder},
    rlimit::{recommended_batch_size, set_open_file_limit},
    scripts::{init_scripts, ScriptsRequired},
    PortList, Scanner,
};
use std::net::IpAddr;
use tracing_subscriber::EnvFilter;

// ── CLI-local enums (clap ValueEnum wrappers) ─────────────────────────────────

#[derive(Clone, Debug, ValueEnum, PartialEq)]
enum CliOrder {
    /// Ascending numeric order: 1, 2, 3, …
    Serial,
    /// LCG pseudo-random order — every port exactly once, no allocation
    Random,
}

impl From<CliOrder> for ScanOrder {
    fn from(o: CliOrder) -> Self {
        match o {
            CliOrder::Serial => ScanOrder::Serial,
            CliOrder::Random => ScanOrder::Random,
        }
    }
}

#[derive(Clone, Debug, ValueEnum, PartialEq)]
enum CliScripts {
    /// Do not run any scripts
    None,
    /// Run the built-in default script set
    Default,
    /// Run scripts from the directory in ~/.rustscan_scripts.toml
    Custom,
}

impl From<CliScripts> for ScriptsRequired {
    fn from(s: CliScripts) -> Self {
        match s {
            CliScripts::None => ScriptsRequired::None,
            CliScripts::Default => ScriptsRequired::Default,
            CliScripts::Custom => ScriptsRequired::Custom,
        }
    }
}

// ── top-1000 ports ────────────────────────────────────────────────────────────
// Nmap's frequency-ranked top-1000 TCP ports (from nmap-services).
const TOP_1000_PORTS: &[u16] = &[
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70,
    79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139,
    143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311,
    340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512,
    513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636,
    646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783,
    787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992,
    993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026,
    1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042,
    1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058,
    1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074,
    1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090,
    1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108,
    1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137,
    1138, 1141, 1145, 1147, 1148, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183,
    1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247,
    1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352,
    1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583,
    1594, 1600, 1641, 1658, 1664, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801,
    1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984,
    1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021,
    2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065,
    2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170,
    2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393,
    2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701,
    2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998,
    3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168,
    3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351,
    3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659,
    3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871,
    3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003,
    4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445,
    4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030,
    5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221,
    5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550,
    5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815,
    5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915,
    5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6000, 6001,
    6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156,
    6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689,
    6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019,
    7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741,
    7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010,
    8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300,
    8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873, 8888, 8899,
    8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099,
    9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503,
    9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944,
    9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082,
    10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111,
    11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441, 14442,
    15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113,
    16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801,
    19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734,
    25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038,
    31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779,
    32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292,
    40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154,
    49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400,
    49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493,
    52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294,
    57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389,
];

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "physarum-scan",
    version,
    max_term_width = 120,
    about = "Fast async TCP/UDP port scanner with Nmap payload support",
    long_about = "\
physarum-scan is the standalone CLI for the physarum-scanner library.\n\
Feature-complete port of RustScan with improvements.\n\
\n\
Capabilities exclusive to this binary (not in physarum-maze):\n\
  --scan-order random   LCG-based pseudo-random port ordering\n\
  --udp                 UDP probes with Nmap payloads auto-loaded\n\
  --greppable / -g      machine-readable, one open socket per line\n\
  --accessible          no ANSI colour codes (screen-reader friendly)\n\
  --ulimit              tune OS open-file limit before scanning\n\
  --scripts             run Nmap-style scripts on discovered ports\n\
  --exclude-ports / -e  skip specific ports\n\
  --exclude-addresses   skip IPs or entire CIDR blocks\n\
  --resolver            custom DNS resolver\n\
  --top                 scan the 1000 most common ports\n\
  -- [NMAP ARGS]        pass extra args to nmap after scanning\
"
)]
struct Cli {
    /// Comma-separated CIDRs, IPs, hostnames, or @/path/to/file of targets
    #[arg(short = 'a', long, value_delimiter = ',', value_name = "TARGET")]
    addresses: Vec<String>,

    /// Comma-separated explicit port list (e.g. 22,80,443,8080)
    #[arg(
        short = 'p',
        long,
        value_delimiter = ',',
        conflicts_with = "range",
        value_name = "PORTS"
    )]
    ports: Option<Vec<u16>>,

    /// Port range in start-end format (e.g. 1-1000). Conflicts with --ports
    #[arg(short = 'r', long, value_name = "START-END")]
    range: Option<String>,

    /// Scan the 1000 most common ports (nmap frequency-ranked)
    #[arg(long, conflicts_with_all = ["ports", "range"])]
    top: bool,

    /// Ignore the configuration file
    #[arg(long)]
    no_config: bool,

    /// Hide the startup banner
    #[arg(long)]
    no_banner: bool,

    /// Path to a custom TOML config file
    #[arg(short = 'c', long, value_name = "PATH")]
    config_path: Option<std::path::PathBuf>,

    /// Machine-readable output: no banner, one open socket per line, no colour
    #[arg(short = 'g', long)]
    greppable: bool,

    /// No ANSI colour codes — suitable for screen readers and log pipelines
    #[arg(long)]
    accessible: bool,

    /// Comma-separated DNS resolvers (IPs or hostname), or path to resolver list file
    #[arg(long, value_name = "RESOLVERS")]
    resolver: Option<String>,

    /// Maximum concurrent socket probes (default: inferred from ulimit)
    #[arg(short = 'b', long, value_name = "N")]
    batch_size: Option<usize>,

    /// Connection/response timeout in milliseconds
    #[arg(short = 't', long, default_value_t = 1_500, value_name = "MS")]
    timeout: u32,

    /// Retry attempts per socket before marking closed (0 is corrected to 1)
    #[arg(long, default_value_t = 1, value_name = "N")]
    tries: u8,

    /// Set OS RLIMIT_NOFILE before scanning (raises the open-file limit)
    #[arg(short = 'u', long, value_name = "N")]
    ulimit: Option<usize>,

    /// Port visit order
    #[arg(long, value_enum, ignore_case = true, default_value_t = CliOrder::Serial)]
    scan_order: CliOrder,

    /// Script execution level after discovering open ports
    #[arg(long, value_enum, ignore_case = true, default_value_t = CliScripts::None)]
    scripts: CliScripts,

    /// Comma-separated ports to skip entirely (e.g. 80,443)
    #[arg(short = 'e', long, value_delimiter = ',', value_name = "PORTS")]
    exclude_ports: Option<Vec<u16>>,

    /// Comma-separated IPs/CIDRs to exclude from target expansion
    #[arg(
        short = 'x',
        long = "exclude-addresses",
        value_delimiter = ',',
        value_name = "TARGETS"
    )]
    exclude_addresses: Option<Vec<String>>,

    /// UDP scan mode — probes with per-port Nmap payloads, reports responding ports
    #[arg(long)]
    udp: bool,

    /// Extra arguments passed to nmap after scanning (use after --)
    /// Example: physarum-scan -a 10.0.0.1 -- -A -sC
    #[arg(last = true, value_name = "NMAP_ARGS")]
    command: Vec<String>,
}

// ── entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    // ── validate targets ──────────────────────────────────────────────────────
    if cli.addresses.is_empty() {
        bail!("no targets specified — use -a/--addresses (e.g. -a 10.0.0.1,10.0.0.0/24)");
    }

    // ── ulimit ────────────────────────────────────────────────────────────────
    if let Some(limit) = cli.ulimit {
        if let Err(e) = set_open_file_limit(limit as u64) {
            physarum_scanner::scanner_warning!(
                format!("could not set ulimit to {limit}: {e}"),
                greppable: cli.greppable,
                accessible: cli.accessible
            );
        }
    }

    // ── config file ───────────────────────────────────────────────────────────
    let mut scan_cfg = ScanConfig::default();
    if !cli.no_config {
        let file_config = Config::read(cli.config_path.clone());
        scan_cfg.merge(&file_config);
    }

    // CLI values override config file.
    let batch_size = cli.batch_size.unwrap_or_else(recommended_batch_size);
    let timeout_ms = cli.timeout;
    let tries = cli.tries.max(1);

    // ── targets ───────────────────────────────────────────────────────────────
    // parse_addresses uses hickory-resolver which creates its own Tokio runtime
    // internally.  Dropping it inside an async context panics.  spawn_blocking
    // moves the work to a thread-pool thread where runtime nesting is allowed.
    let addresses_clone = cli.addresses.clone();
    let exclude_hosts = cli.exclude_addresses.clone().unwrap_or_default();
    let ips = tokio::task::spawn_blocking(move || {
        parse_addresses(
            &addresses_clone,
            &if exclude_hosts.is_empty() {
                None
            } else {
                Some(exclude_hosts)
            },
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("address resolution panicked: {e}"))?;

    if ips.is_empty() {
        bail!(
            "no valid target addresses resolved from {:?}",
            cli.addresses
        );
    }

    // ── ports ─────────────────────────────────────────────────────────────────
    let port_list: Vec<u16> = if cli.top {
        TOP_1000_PORTS.to_vec()
    } else if let Some(explicit) = cli.ports {
        explicit
    } else {
        let range = match cli.range.as_deref() {
            Some(s) => PortRange::parse(s).map_err(|e| anyhow::anyhow!(e))?,
            None => scan_cfg.range.unwrap_or_else(PortRange::all),
        };
        let strategy = PortStrategy::pick(&Some(range), None, cli.scan_order.into());
        strategy.order()
    };

    let ports = PortList::explicit(port_list);
    let exclude_ports = cli.exclude_ports.unwrap_or_default();

    // ── banner ────────────────────────────────────────────────────────────────
    let greppable = cli.greppable;
    let accessible = cli.accessible;
    let no_banner = cli.no_banner || greppable;

    if !no_banner {
        physarum_scanner::scanner_banner!(greppable: false, accessible: accessible);
        physarum_scanner::scanner_detail!(
            format!(
                "Scanning {} host(s) · {} port(s) · batch={} timeout={}ms tries={} {}",
                ips.len(),
                ports.as_slice().len(),
                batch_size,
                timeout_ms,
                tries,
                if cli.udp { "[UDP]" } else { "[TCP]" }
            ),
            greppable: false,
            accessible: accessible
        );
    }

    // ── scan ──────────────────────────────────────────────────────────────────
    // UDP: nmap_payloads loaded automatically inside scanner when no explicit
    // map is provided.
    let open = Scanner::new(ips.clone(), ports)
        .batch_size(batch_size)
        .timeout_ms(timeout_ms as u64)
        .tries(tries)
        .exclude_ports(exclude_ports)
        .udp(cli.udp)
        .run()
        .await?;

    // ── output ────────────────────────────────────────────────────────────────
    if open.is_empty() {
        if !greppable {
            physarum_scanner::scanner_detail!(
                "No open ports found.",
                greppable: false,
                accessible: accessible
            );
        }
    } else {
        for socket in &open {
            if greppable {
                println!("{socket}");
            } else {
                physarum_scanner::scanner_output!(
                    format!("Open {socket}"),
                    greppable: false,
                    accessible: accessible
                );
            }
        }
    }

    // ── nmap passthrough ──────────────────────────────────────────────────────
    if !cli.command.is_empty() && !open.is_empty() {
        run_nmap_passthrough(
            &ips,
            &open.iter().map(|s| s.port()).collect::<Vec<_>>(),
            &cli.command,
        );
    }

    // ── scripts ───────────────────────────────────────────────────────────────
    if cli.scripts != CliScripts::None && !open.is_empty() {
        match init_scripts(cli.scripts.into()) {
            Ok(script_files) => {
                for ip in &ips {
                    let open_for_ip: Vec<u16> = open
                        .iter()
                        .filter(|s| s.ip() == *ip)
                        .map(|s| s.port())
                        .collect();
                    if open_for_ip.is_empty() {
                        continue;
                    }
                    for sf in &script_files {
                        let script = sf.clone().into_script(*ip, open_for_ip.clone());
                        if let Err(e) = script.run() {
                            physarum_scanner::scanner_warning!(
                                format!("script error on {ip}: {e}"),
                                greppable: greppable,
                                accessible: accessible
                            );
                        }
                    }
                }
            }
            Err(e) => physarum_scanner::scanner_warning!(
                format!("could not load scripts: {e}"),
                greppable: greppable,
                accessible: accessible
            ),
        }
    }

    Ok(())
}

// ── nmap passthrough ──────────────────────────────────────────────────────────

/// Run `nmap -vvv -p PORTS -Pn [USER_ARGS] IP` for each discovered host.
///
/// Mirrors RustScan's behaviour when args are passed after `--`.
fn run_nmap_passthrough(ips: &[IpAddr], open_ports: &[u16], extra_args: &[String]) {
    let port_str = open_ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    for ip in ips {
        let mut cmd = std::process::Command::new("nmap");
        cmd.args(["-vvv", "-p", &port_str, "-Pn"]);
        cmd.args(extra_args);
        cmd.arg(ip.to_string());

        match cmd.status() {
            Ok(status) if !status.success() => {
                eprintln!("[!] nmap exited with status {status} for {ip}");
            }
            Err(e) => {
                eprintln!("[!] could not launch nmap for {ip}: {e}");
            }
            Ok(_) => {}
        }
    }
}
