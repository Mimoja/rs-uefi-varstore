use std::collections::BTreeMap;

use crate::attribute::EfiAttribute;

#[derive(Debug, Clone)]
pub struct EfiVariable {
    pub data: Vec<u8>,
    pub attr: EfiAttribute,
}

impl EfiVariable {
    fn new(data: Vec<u8>, attr: EfiAttribute) -> EfiVariable {
        EfiVariable { data, attr }
    }
}

#[derive(Debug)]
pub struct Varstore {
    variables: BTreeMap<String, EfiVariable>,
    bootservices_exited: bool,
    max_data_length: usize,
    max_name_length: usize,
}

impl Varstore {
    pub fn new() -> Varstore {
        Varstore {
            variables: BTreeMap::new(),
            bootservices_exited: false,
            max_name_length: 10000,
            max_data_length: 50000,
        }
    }

    pub fn with_limits(max_name: usize, max_data: usize) -> Varstore {
        Varstore {
            variables: BTreeMap::new(),
            bootservices_exited: false,
            max_data_length: max_data,
            max_name_length: max_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varstore_creating() {
        let varstore = Varstore::with_limits(42, 690);
        assert_eq!(varstore.max_name_length, 42);
        assert_eq!(varstore.max_data_length, 690);
    }
}
