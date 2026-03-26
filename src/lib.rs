use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

mod cbc;
mod ctr;
mod ige;

const AES_BLOCK_SIZE: usize = 16;

fn validate_ige(data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<()> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if data.len() % AES_BLOCK_SIZE != 0 {
        return Err(PyValueError::new_err(
            "Data size must match a multiple of 16 bytes",
        ));
    }
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 32 {
        return Err(PyValueError::new_err("IV size must be exactly 32 bytes"));
    }
    Ok(())
}

fn validate_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<()> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if data.len() % AES_BLOCK_SIZE != 0 {
        return Err(PyValueError::new_err(
            "Data size must match a multiple of 16 bytes",
        ));
    }
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(PyValueError::new_err("IV size must be exactly 16 bytes"));
    }
    Ok(())
}

fn validate_ctr(data: &[u8], key: &[u8], iv: &[u8], state: &[u8]) -> PyResult<()> {
    if data.is_empty() {
        return Err(PyValueError::new_err("Data must not be empty"));
    }
    if key.len() != 32 {
        return Err(PyValueError::new_err("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 16 {
        return Err(PyValueError::new_err("IV size must be exactly 16 bytes"));
    }
    if state.len() != 1 {
        return Err(PyValueError::new_err("State size must be exactly 1 byte"));
    }
    if state[0] > 15 {
        return Err(PyValueError::new_err(
            "State value must be in the range [0, 15]",
        ));
    }
    Ok(())
}

/// AES-256-IGE Encryption
#[pyfunction]
fn ige256_encrypt<'py>(
    py: Python<'py>,
    data: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
) -> PyResult<Bound<'py, PyBytes>> {
    validate_ige(&data, &key, &iv)?;
    let key: [u8; 32] = key.try_into().unwrap();
    let iv: [u8; 32] = iv.try_into().unwrap();
    let result = py.detach(|| ige::encrypt(&data, &key, &iv));
    Ok(PyBytes::new(py, &result))
}

/// AES-256-IGE Decryption
#[pyfunction]
fn ige256_decrypt<'py>(
    py: Python<'py>,
    data: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
) -> PyResult<Bound<'py, PyBytes>> {
    validate_ige(&data, &key, &iv)?;
    let key: [u8; 32] = key.try_into().unwrap();
    let iv: [u8; 32] = iv.try_into().unwrap();
    let result = py.detach(|| ige::decrypt(&data, &key, &iv));
    Ok(PyBytes::new(py, &result))
}

fn ctr_impl<'py>(
    py: Python<'py>,
    data: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
    state: Vec<u8>,
) -> PyResult<Bound<'py, PyBytes>> {
    validate_ctr(&data, &key, &iv, &state)?;
    let key: [u8; 32] = key.try_into().unwrap();
    let mut iv: [u8; 16] = iv.try_into().unwrap();
    let mut state_val = state[0];
    let result = py.detach(|| ctr::ctr256(&data, &key, &mut iv, &mut state_val));
    Ok(PyBytes::new(py, &result))
}

/// AES-256-CTR Encryption
#[pyfunction]
fn ctr256_encrypt<'py>(
    py: Python<'py>,
    data: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
    state: Vec<u8>,
) -> PyResult<Bound<'py, PyBytes>> {
    ctr_impl(py, data, key, iv, state)
}

/// AES-256-CTR Decryption (identical to encryption in CTR mode)
#[pyfunction]
fn ctr256_decrypt<'py>(
    py: Python<'py>,
    data: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
    state: Vec<u8>,
) -> PyResult<Bound<'py, PyBytes>> {
    ctr_impl(py, data, key, iv, state)
}

/// AES-256-CBC Encryption
#[pyfunction]
fn cbc256_encrypt<'py>(
    py: Python<'py>,
    data: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
) -> PyResult<Bound<'py, PyBytes>> {
    validate_cbc(&data, &key, &iv)?;
    let key: [u8; 32] = key.try_into().unwrap();
    let mut iv: [u8; 16] = iv.try_into().unwrap();
    let result = py.detach(|| cbc::encrypt(&data, &key, &mut iv));
    Ok(PyBytes::new(py, &result))
}

/// AES-256-CBC Decryption
#[pyfunction]
fn cbc256_decrypt<'py>(
    py: Python<'py>,
    data: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
) -> PyResult<Bound<'py, PyBytes>> {
    validate_cbc(&data, &key, &iv)?;
    let key: [u8; 32] = key.try_into().unwrap();
    let mut iv: [u8; 16] = iv.try_into().unwrap();
    let result = py.detach(|| cbc::decrypt(&data, &key, &mut iv));
    Ok(PyBytes::new(py, &result))
}

#[pymodule]
fn tgcrypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(ige256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ige256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(cbc256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(cbc256_decrypt, m)?)?;
    Ok(())
}
