use std::convert::TryFrom;

/// format of bpf instruction
#[repr(C)]
#[derive(Clone, Debug)]
pub struct Instruction {
    code: u8,
    dst_reg: u8,
    src_reg: u8,
    offset: usize,
    imm: usize,
}

#[derive(Clone, Debug)]
pub struct Instructions {
    inner: Vec<Instruction>,
}

impl Instructions {
    pub fn from_vec(v: Vec<u8>) -> Instructions {
        debug_assert!(v.len() % 8 == 0);
        let mut inner: Vec<Instruction> = Vec::with_capacity(v.len() / 8);
        for i in (0..v.len()).step_by(8) {
            let s = &v.as_slice()[i..(i + 8)];
            let code = s[0];
            let dst_reg = s[1] & 0x0F;
            let src_reg = (s[1] & 0xF0) >> 4;
            let offset = u16::from_be_bytes(<[u8; 2]>::try_from(&s[2..4]).unwrap()) as usize;
            let imm = u32::from_be_bytes(<[u8; 4]>::try_from(&s[4..8]).unwrap()) as usize;
            inner.push(Instruction {
                code,
                dst_reg,
                src_reg,
                offset,
                imm,
            });
        }
        Instructions { inner }
    }

    pub fn inner(&self) -> &Vec<Instruction> {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &Vec<Instruction> {
        &mut self.inner
    }
}
