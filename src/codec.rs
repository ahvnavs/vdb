use crate::error::{Result, corruption};

pub(crate) struct Encoder(Vec<u8>);
impl Encoder {
    pub(crate) fn new(domain: &[u8]) -> Self {
        Self(domain.to_vec())
    }
    pub(crate) fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    pub(crate) fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub(crate) fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.0.extend_from_slice(value);
    }
    pub(crate) fn string(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }
    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }
}

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Decoder<'a> {
    pub(crate) fn new(bytes: &'a [u8], domain: &[u8]) -> Result<Self> {
        if !bytes.starts_with(domain) {
            return Err(corruption("invalid canonical record domain"));
        }
        Ok(Self {
            bytes,
            offset: domain.len(),
        })
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| corruption("record length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| corruption("truncated canonical record"))?;
        self.offset = end;
        Ok(value)
    }
    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(corruption)?,
        ))
    }
    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(corruption)?,
        ))
    }
    pub(crate) fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = usize::try_from(self.u64()?).map_err(corruption)?;
        if len > max {
            return Err(corruption("canonical field exceeds size limit"));
        }
        self.take(len)
    }
    pub(crate) fn string(&mut self, max: usize) -> Result<String> {
        String::from_utf8(self.bytes(max)?.to_vec()).map_err(corruption)
    }
    pub(crate) fn finish(self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(corruption("trailing bytes in canonical record"));
        }
        Ok(())
    }
}
