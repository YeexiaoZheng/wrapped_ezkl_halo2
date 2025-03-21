use crate::poly::Polynomial;
use ff::PrimeField;
use halo2curves::{serde::SerdeObject, CurveAffine};
use std::io;

/// This enum specifies how various types are serialized and deserialized.
#[derive(Clone, Copy, Debug)]
pub enum SerdeFormat {
    /// Curve elements are serialized in compressed form.
    /// Field elements are serialized in standard form, with endianness specified by the
    /// `PrimeField` implementation.
    Processed,
    /// Curve elements are serialized in uncompressed form. Field elements are serialized
    /// in their internal Montgomery representation.
    /// When deserializing, checks are performed to ensure curve elements indeed lie on the curve and field elements
    /// are less than modulus.
    RawBytes,
    /// Serialization is the same as `RawBytes`, but no checks are performed.
    RawBytesUnchecked,
}

// Keep this trait for compatibility with IPA serialization
pub(crate) trait CurveRead: CurveAffine {
    /// Reads a compressed element from the buffer and attempts to parse it
    /// using `from_bytes`.
    fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let mut compressed = Self::Repr::default();
        reader.read_exact(compressed.as_mut())?;
        Option::from(Self::from_bytes(&compressed))
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid point encoding in proof"))
    }
}
impl<C: CurveAffine> CurveRead for C {}

pub trait SerdeCurveAffine: CurveAffine + SerdeObject {
    /// Reads an element from the buffer and parses it according to the `format`:
    /// - `Processed`: Reads a compressed curve element and decompress it
    /// - `RawBytes`: Reads an uncompressed curve element with coordinates in Montgomery form.
    /// Checks that field elements are less than modulus, and then checks that the point is on the curve.
    /// - `RawBytesUnchecked`: Reads an uncompressed curve element with coordinates in Montgomery form;
    /// does not perform any checks
    fn read<R: io::Read>(reader: &mut R, format: SerdeFormat) -> io::Result<Self> {
        match format {
            SerdeFormat::Processed => <Self as CurveRead>::read(reader),
            SerdeFormat::RawBytes => <Self as SerdeObject>::read_raw(reader),
            SerdeFormat::RawBytesUnchecked => Ok(<Self as SerdeObject>::read_raw_unchecked(reader)),
        }
    }
    /// Writes a curve element according to `format`:
    /// - `Processed`: Writes a compressed curve element
    /// - Otherwise: Writes an uncompressed curve element with coordinates in Montgomery form
    fn write<W: io::Write>(&self, writer: &mut W, format: SerdeFormat) -> io::Result<()> {
        match format {
            SerdeFormat::Processed => writer.write_all(self.to_bytes().as_ref()),
            _ => self.write_raw(writer),
        }
    }

    /// Byte length of an affine curve element according to `format`.
    fn byte_length(format: SerdeFormat) -> usize {
        match format {
            SerdeFormat::Processed => Self::default().to_bytes().as_ref().len(),
            _ => Self::Repr::default().as_ref().len() * 2,
        }
    }
}
impl<C: CurveAffine + SerdeObject> SerdeCurveAffine for C {}

///
pub trait SerdePrimeField: PrimeField + SerdeObject {
    /// Reads a field element as bytes from the buffer according to the `format`:
    /// - `Processed`: Reads a field element in standard form, with endianness specified by the
    /// `PrimeField` implementation, and checks that the element is less than the modulus.
    /// - `RawBytes`: Reads a field element from raw bytes in its internal Montgomery representations,
    /// and checks that the element is less than the modulus.
    /// - `RawBytesUnchecked`: Reads a field element in Montgomery form and performs no checks.
    fn read<R: io::Read>(reader: &mut R, format: SerdeFormat) -> io::Result<Self> {
        match format {
            SerdeFormat::Processed => {
                let mut compressed = Self::Repr::default();
                reader.read_exact(compressed.as_mut())?;
                Option::from(Self::from_repr(compressed)).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Other, "Invalid prime field point encoding")
                })
            }
            SerdeFormat::RawBytes => <Self as SerdeObject>::read_raw(reader),
            SerdeFormat::RawBytesUnchecked => Ok(<Self as SerdeObject>::read_raw_unchecked(reader)),
        }
    }

    /// Writes a field element as bytes to the buffer according to the `format`:
    /// - `Processed`: Writes a field element in standard form, with endianness specified by the
    ///  `PrimeField` implementation.
    /// - Otherwise: Writes a field element into raw bytes in its internal Montgomery representation,
    /// WITHOUT performing the expensive Montgomery reduction.
    fn write<W: io::Write>(&self, writer: &mut W, format: SerdeFormat) -> io::Result<()> {
        match format {
            SerdeFormat::Processed => writer.write_all(self.to_repr().as_ref()),
            _ => self.write_raw(writer),
        }
    }
}
impl<F: PrimeField + SerdeObject> SerdePrimeField for F {}

/// Convert a slice of `bool` into a `u8`.
///
/// Panics if the slice has length greater than 8.
pub fn pack(bits: &[bool]) -> u8 {
    let mut value = 0u8;
    assert!(bits.len() <= 8);
    for (bit_index, bit) in bits.iter().enumerate() {
        value |= (*bit as u8) << bit_index;
    }
    value
}

/// Writes the first `bits.len()` bits of a `u8` into `bits`.
pub fn unpack(byte: u8, bits: &mut [bool]) {
    for (bit_index, bit) in bits.iter_mut().enumerate() {
        *bit = (byte >> bit_index) & 1 == 1;
    }
}

#[cfg(not(feature = "parallel-poly-read"))]
/// Reads a vector of polynomials from buffer
pub(crate) fn read_polynomial_vec<R: io::Read, F: SerdePrimeField, B>(
    reader: &mut R,
    format: SerdeFormat,
) -> io::Result<Vec<Polynomial<F, B>>> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len);

    let poly_lens: Result<Vec<_>, _> = (0..len)
        .map(|_| {
            let mut poly_len = [0u8; 4];
            reader.read_exact(&mut poly_len)?;
            Ok::<_, std::io::Error>(u32::from_be_bytes(poly_len))
        })
        .collect();

    let _poly_lens = poly_lens?;

    (0..len)
        .map(|_| Polynomial::<F, B>::read(reader, format))
        .collect::<io::Result<Vec<_>>>()
}

#[cfg(feature = "parallel-poly-read")]
/// Reads a vector of polynomials from buffer
pub(crate) fn read_polynomial_vec<R: io::Read, F: SerdePrimeField, B: std::marker::Send>(
    reader: &mut R,
    format: SerdeFormat,
) -> io::Result<Vec<Polynomial<F, B>>> {
    use maybe_rayon::iter::IntoParallelIterator;
    use maybe_rayon::iter::ParallelIterator;

    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len);

    // Read all polynomial lengths first
    let mut poly_lens = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let mut poly_len = [0u8; 4];
        reader.read_exact(&mut poly_len)?;
        poly_lens.push(u32::from_be_bytes(poly_len));
    }

    // Pre-read all polynomial data into separate buffers
    let mut poly_buffers = Vec::with_capacity(len as usize);
    for &poly_len in &poly_lens {
        let repr_len = F::default().to_repr().as_ref().len();
        // sum of all the Field elements AND also the prepended u32 bytes
        let buffer_size = repr_len * poly_len as usize + std::mem::size_of::<u32>();
        let mut buffer = vec![0u8; buffer_size];
        reader.read_exact(&mut buffer)?;
        poly_buffers.push(buffer);
    }

    // Process buffers in parallel
    poly_buffers
        .into_par_iter()
        .map(|buffer| {
            let mut cursor = std::io::Cursor::new(buffer);
            Polynomial::<F, B>::read_serial(&mut cursor, format)
        })
        .collect::<io::Result<Vec<_>>>()
}

/// Writes a slice of polynomials to buffer
pub(crate) fn write_polynomial_slice<W: io::Write, F: SerdePrimeField, B>(
    slice: &[Polynomial<F, B>],
    writer: &mut W,
    format: SerdeFormat,
) -> io::Result<()> {
    writer.write_all(&(slice.len() as u32).to_be_bytes())?;
    // then write each polynomial's len
    for poly in slice.iter() {
        writer.write_all(&(poly.num_coeffs() as u32).to_be_bytes())?;
    }

    for poly in slice.iter() {
        poly.write(writer, format)?;
    }
    Ok(())
}

/// Gets the total number of bytes of a slice of polynomials, assuming all polynomials are the same length
pub(crate) fn polynomial_slice_byte_length<F: PrimeField, B>(slice: &[Polynomial<F, B>]) -> usize {
    let field_len = F::default().to_repr().as_ref().len();
    4 + 4 * slice.len()
        + slice.len() * (4 + field_len * slice.first().map(|poly| poly.len()).unwrap_or(0))
}
