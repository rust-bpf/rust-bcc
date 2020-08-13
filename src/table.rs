use bcc_sys::bccapi::*;
use libc::{c_int, size_t};

use crate::types::MutPointer;
use crate::BccError;

use std::ffi::CStr;

#[derive(Clone, Debug)]
pub struct Table {
    id: size_t,
    p: MutPointer,
}

impl Table {
    pub fn new(id: usize, p: MutPointer) -> Table {
        Table { id, p }
    }

    /// Returns the size, in bytes, of keys in the `Table`
    pub fn key_size(&mut self) -> usize {
        unsafe { bpf_table_key_size_id(self.p, self.id) }
    }

    pub fn fd(&mut self) -> c_int {
        unsafe { bpf_table_fd_id(self.p, self.id) }
    }

    /// Returns the size, in bytes, of leaf nodes in the `Table`
    pub fn leaf_size(&mut self) -> usize {
        unsafe { bpf_table_leaf_size_id(self.p, self.id) }
    }

    /// Returns the name of the `Table`
    pub fn name(&mut self) -> String {
        unsafe {
            let cs = bpf_table_name(self.p, self.id);
            CStr::from_ptr(cs).to_str().unwrap().to_string()
        }
    }

    /// Delete the provided key and associated leaf node from the `Table`
    pub fn delete(&mut self, key: &mut [u8]) -> Result<(), BccError> {
        let fd = self.fd();
        let res = unsafe { bpf_delete_elem(fd, key.as_mut_ptr() as MutPointer) };
        match res {
            0 => Ok(()),
            _ => Err(BccError::DeleteTableValue),
        }
    }

    /// Delete all keys and associated leaf nodes from the `Table`
    pub fn delete_all(&mut self) -> Result<(), BccError> {
        for mut e in self.iter() {
            self.delete(&mut e.key)?;
        }
        Ok(())
    }

    /// Get the leaf node associated with the provided key
    pub fn get(&mut self, key: &mut [u8]) -> Result<Vec<u8>, BccError> {
        let mut leaf = vec![0; self.leaf_size()];
        let res = unsafe {
            bpf_lookup_elem(
                self.fd(),
                key.as_mut_ptr() as MutPointer,
                leaf.as_mut_ptr() as MutPointer,
            )
        };
        match res {
            0 => Ok(leaf),
            _ => Err(BccError::GetTableValue),
        }
    }

    /// Store the provided leaf node for the provided key
    pub fn set(&mut self, key: &mut [u8], leaf: &mut [u8]) -> Result<(), BccError> {
        let res = unsafe {
            bpf_update_elem(
                self.fd(),
                key.as_mut_ptr() as MutPointer,
                leaf.as_mut_ptr() as MutPointer,
                0,
            )
        };
        // TODO: maybe we can get an errno here to enhance the error message with?
        match res {
            0 => Ok(()),
            _ => Err(BccError::SetTableValue),
        }
    }

    /// Create an iterator for key/leaf pairs in the `Table`
    pub fn iter(&self) -> EntryIter {
        EntryIter {
            current: None,
            table: self.clone(),
            fd: None,
        }
    }
}

impl IntoIterator for Table {
    type Item = Entry;
    type IntoIter = EntryIter;
    fn into_iter(self) -> Self::IntoIter {
        EntryIter {
            current: None,
            table: self,
            fd: None,
        }
    }
}

impl<'a> IntoIterator for &'a Table {
    type Item = Entry;
    type IntoIter = EntryIter;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Clone)]
pub struct Entry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

pub struct EntryIter {
    current: Option<Entry>,
    fd: Option<c_int>,
    table: Table,
}

impl EntryIter {
    pub fn entry_ptrs(&mut self) -> Option<(MutPointer, MutPointer)> {
        match self.current.as_mut() {
            Some(&mut Entry {
                ref mut key,
                ref mut value,
            }) => Some((
                key.as_mut_ptr() as MutPointer,
                value.as_mut_ptr() as MutPointer,
            )),
            None => None,
        }
    }

    pub fn start(&mut self) -> Option<Entry> {
        self.fd = Some(self.table.fd());
        let key_size = self.table.key_size();
        let leaf_size = self.table.leaf_size();
        let entry = Entry {
            key: vec![0; key_size],
            value: vec![0; leaf_size],
        };
        self.current = Some(entry);
        unsafe {
            let (k, v) = self.entry_ptrs().unwrap();
            if bpf_get_first_key(self.fd.unwrap(), k, key_size) < 0 {
                self.current = None;
            } else {
                bpf_lookup_elem(self.fd.unwrap(), k, v);
            }
        }
        self.current.clone()
    }
}

impl Iterator for EntryIter {
    type Item = Entry;

    fn next(&mut self) -> Option<Entry> {
        if let Some((k, l)) = self.entry_ptrs() {
            let fd = self.fd.expect("oh no");
            match unsafe { bpf_get_next_key(fd, k, k) } {
                -1 => None,
                _ => {
                    unsafe { bpf_lookup_elem(fd, k, l) };
                    self.current.clone()
                }
            }
        } else {
            self.start()
        }
    }
}
