use anyhow::{self, bail, Result};

use std::fs::File;
use std::io::Read;
use std::str::FromStr;

const CPUONLINE: &str = "/sys/devices/system/cpu/online";

// loosely based on https://github.com/iovisor/bcc/blob/v0.3.0/src/python/bcc/utils.py#L15
fn read_cpu_range(cpu_range_str: &str) -> Result<Vec<usize>> {
    let mut cpus = Vec::new();
    let cpu_range_str_trim = cpu_range_str.trim();
    for cpu_range in cpu_range_str_trim.split(',') {
        let rangeop: Vec<&str> = cpu_range.splitn(2, '-').collect();
        let first = match usize::from_str(rangeop[0]) {
            Ok(res) => res,
            Err(e) => bail!(anyhow::anyhow!("Fail to recognize first cpu number: {}", e)),
        };
        if rangeop.len() == 1 {
            cpus.push(first);
            continue;
        }
        let last = match usize::from_str(rangeop[1]) {
            Ok(res) => res,
            Err(e) => bail!(anyhow::anyhow!(
                "Fail to recognize second cpu number: {}",
                e
            )),
        };
        for n in first..=last {
            cpus.push(n);
        }
    }
    Ok(cpus)
}

pub fn get() -> Result<Vec<usize>> {
    let mut buffer = String::new();
    File::open(CPUONLINE)?.read_to_string(&mut buffer)?;
    read_cpu_range(&buffer)
}

#[cfg(test)]
mod tests {
    use super::read_cpu_range;

    use lazy_static::*;

    struct TestData<'a> {
        data: &'a str,
        expected: Vec<usize>,
        valid: bool,
    }

    lazy_static! {
        static ref TEST: Vec<TestData<'static>> = vec![
            TestData {
                data: "",
                expected: Vec::new(),
                valid: false,
            },
            TestData {
                data: "0-3\n",
                expected: vec![0, 1, 2, 3],
                valid: true,
            },
            TestData {
                data: "   0-2,5",
                expected: vec![0, 1, 2, 5],
                valid: true,
            },
            TestData {
                data: "0,2,4-5,7-9",
                expected: vec![0, 2, 4, 5, 7, 8, 9],
                valid: true,
            },
            TestData {
                data: "0,2",
                expected: vec![0, 2],
                valid: true,
            },
            TestData {
                data: "0",
                expected: vec![0],
                valid: true,
            },
            TestData {
                data: "-2,5",
                expected: Vec::new(),
                valid: false,
            },
            TestData {
                data: "2-@,5",
                expected: Vec::new(),
                valid: false,
            },
            TestData {
                data: "-",
                expected: Vec::new(),
                valid: false,
            },
        ];
    }
    #[test]
    fn test_cpu_online() {
        for i in 0..TEST.len() {
            let t = &TEST[i];
            let res = read_cpu_range(t.data);
            assert!((t.valid && res.is_ok()) || (!t.valid && res.is_err()));
            if let Ok(v) = res {
                for i in 0..v.len() {
                    assert_eq!(v[i], t.expected[i]);
                }
            }
        }
    }
}
