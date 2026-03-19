/// Trait for ENet packet compression/decompression.
///
/// Implement this trait to provide custom compression for ENet packets.
/// The compressor is set via [`crate::Host::set_compressor()`].
pub trait Compressor: Send {
    /// Compress the input data into the output buffer.
    ///
    /// Returns the number of bytes written to `output`, or `None` if
    /// compression failed or the compressed data would be larger than the original.
    fn compress(&self, input: &[u8], output: &mut [u8]) -> Option<usize>;

    /// Decompress the input data into the output buffer.
    ///
    /// Returns the number of bytes written to `output`, or `None` if decompression failed.
    fn decompress(&self, input: &[u8], output: &mut [u8]) -> Option<usize>;
}
