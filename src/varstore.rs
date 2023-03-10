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

    fn request_get_next(&self, name: Option<String>) -> Option<(&String, &EfiVariable)> {
        match name {
            Some(var_name) => self
                .variables
                .iter()
                .skip_while(|&(k, _v)| k != &var_name)
                .nth(1),
            None => self.variables.iter().next(),
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

    #[test]
    fn get_next() {
        let mut varstore = Varstore::new();
        let var = EfiVariable::new(
            vec![1, 2, 3, 4],
            EfiAttribute::BOOTSERVICE_ACCESS | EfiAttribute::RUNTIME_ACCESS,
        );
        varstore.variables.insert("Test_1".to_string(), var.clone());
        varstore.variables.insert("Test_2".to_string(), var.clone());
        varstore.variables.insert("Test_3".to_string(), var.clone());
        varstore.variables.insert("Test_4".to_string(), var.clone());

        let mut name = None;
        while let Some((new_name, var)) = varstore.request_get_next(name) {
            name = Some(new_name.to_owned());
            println!("{new_name} {var:?}");
        }

        let first = varstore.request_get_next(None);
        assert!(first.is_some());

        let (name, _var) = first.unwrap();
        assert_eq!(name.to_owned(), "Test_1".to_string());

        let next = varstore.request_get_next(Some(name.to_owned()));
        assert!(next.is_some());
        let (name, _var) = next.unwrap();
        assert_eq!(name.to_owned(), "Test_2");

        let end = varstore.request_get_next(Some("Test_4".to_string()));
        assert!(end.is_none());

        let non_exist = varstore.request_get_next(Some("Test_NonExist".to_string()));
        assert!(non_exist.is_none());
    }
}
