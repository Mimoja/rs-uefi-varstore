use std::collections::BTreeMap;

use crate::attribute::EfiAttribute;
use crate::status::EfiStatus;

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

    fn request_get(&self, name: &String) -> Option<&EfiVariable> {
        if name.is_empty() {
            return None;
        }

        let var = self.variables.get(name);

        if var.is_some()
            && self.bootservices_exited
            && !var.unwrap().attr.contains(EfiAttribute::RUNTIME_ACCESS)
        {
            return None;
        }
        var
    }

    fn request_set(
        &mut self,
        name: &String,
        data: &EfiVariable,
        append: bool,
    ) -> Result<Option<EfiVariable>, EfiStatus> {
        if name.len() > self.max_name_length {
            return Err(EfiStatus::InvalidParameter);
        }

        if data.data.len() > self.max_data_length {
            return Err(EfiStatus::InvalidParameter);
        }

        if data.attr.contains(EfiAttribute::HARDWARE_ERROR) {
            return Err(EfiStatus::InvalidParameter);
        }

        /* Authenticated write access is deprecated and is not supported. */
        if data.attr.contains(EfiAttribute::AUTHENTICATED_WRITE_ACCESS) {
            return Err(EfiStatus::Unsupported);
        }

        /* Only one type of authentication may be used at a time */
        if data.attr.contains(
            EfiAttribute::TIME_BASED_AUTHENTICATED_WRITE_ACCESS
                | EfiAttribute::ENHANCED_AUTHENTICATED_ACCESS,
        ) {
            return Err(EfiStatus::SecurityViolation);
        }

        /* Enhanced authenticated access is not yet implemented. */
        if data
            .attr
            .contains(EfiAttribute::ENHANCED_AUTHENTICATED_ACCESS)
        {
            return Err(EfiStatus::Unsupported);
        }

        /* Time based authenticated access is not yet implemented. */
        if data
            .attr
            .contains(EfiAttribute::TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
        {
            return Err(EfiStatus::Unsupported);
        }

        /* If runtime access is set, bootservice access must also be set. */
        if data.attr.contains(EfiAttribute::RUNTIME_ACCESS)
            && !data.attr.contains(EfiAttribute::BOOTSERVICE_ACCESS)
        {
            return Err(EfiStatus::InvalidParameter);
        }

        let mut new_var = data.clone();
        let old_var = self.variables.get(name);
        if let Some(exist) = old_var {
            if exist.attr != new_var.attr {
                return Err(EfiStatus::InvalidParameter);
            }
            
            if self.bootservices_exited && !new_var.attr.contains(EfiAttribute::RUNTIME_ACCESS)
            {
                return Err(EfiStatus::InvalidParameter);
            }

            if append {
                let mut old_data = exist.data.clone();

                old_data.append(&mut new_var.data);
                new_var.data = old_data;
            /* Zero sized append is a no-op and not a delete */
            } else if new_var.data.len() == 0 {
                self.variables.remove(&name.to_owned());
                return Ok(None);
            }
        }
        self.variables.insert(name.to_owned(), new_var.to_owned());
        Ok(None)
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

    #[test]
    fn get_full_access() {
        let mut varstore = Varstore::new();
        let var = EfiVariable::new(
            vec![1, 2, 3, 4],
            EfiAttribute::BOOTSERVICE_ACCESS | EfiAttribute::RUNTIME_ACCESS,
        );
        varstore
            .variables
            .insert("TestExist".to_string(), var.clone());

        assert!(varstore.request_get(&String::from("TestExist")).is_some());
        assert_eq!(
            varstore
                .request_get(&String::from("TestExist"))
                .unwrap()
                .data,
            vec![1, 2, 3, 4]
        );
        assert!(varstore
            .request_get(&String::from("TestNonExist"))
            .is_none());
    }

    #[test]
    fn get_runtime_access() {
        let mut varstore = Varstore::new();

        let var1 = EfiVariable::new(vec![1, 2, 3, 4], EfiAttribute::BOOTSERVICE_ACCESS);
        varstore
            .variables
            .insert("TestBootservice".to_string(), var1.clone());

        let var2 = EfiVariable::new(
            vec![4, 3, 2, 1],
            EfiAttribute::BOOTSERVICE_ACCESS | EfiAttribute::RUNTIME_ACCESS,
        );
        varstore
            .variables
            .insert("TestRuntime".to_string(), var2.clone());

        assert!(varstore
            .request_get(&String::from("TestBootservice"))
            .is_some());

        varstore.bootservices_exited = true;

        assert!(varstore
            .request_get(&String::from("TestBootservice"))
            .is_none());

        assert!(varstore.request_get(&String::from("TestRuntime")).is_some());
        assert_eq!(
            varstore
                .request_get(&String::from("TestRuntime"))
                .unwrap()
                .data,
            vec![4, 3, 2, 1]
        );
    }

    #[test]
    fn set_simple() {
        let mut varstore = Varstore::new();

        varstore.request_set(
            &String::from("Test1"),
            &mut EfiVariable::new(
                vec![1, 2, 3, 4],
                EfiAttribute::BOOTSERVICE_ACCESS | EfiAttribute::RUNTIME_ACCESS,
            ),
            false
        );
        varstore.request_set(
            &String::from("Test2"),
            &mut EfiVariable::new(
                vec![2, 3, 4, 5],
                EfiAttribute::BOOTSERVICE_ACCESS | EfiAttribute::RUNTIME_ACCESS,
            ),
            false
        );
        varstore.request_set(
            &String::from("Test3"),
            &mut EfiVariable::new(
                vec![3, 4, 5, 6],
                EfiAttribute::BOOTSERVICE_ACCESS | EfiAttribute::RUNTIME_ACCESS,
            ),
            false
        );
        assert_eq!(varstore.variables.len(), 3);
    }

    #[test]
    fn set_delete() {
        let mut varstore = Varstore::new();

        varstore.request_set(
            &String::from("RuntimeAccess"),
            &mut EfiVariable::new(
                vec![1, 2, 3, 4],
                EfiAttribute::BOOTSERVICE_ACCESS | EfiAttribute::RUNTIME_ACCESS,
            ),
            false
        );
        varstore.request_set(
            &String::from("BootAccess"),
            &mut EfiVariable::new(
                vec![2, 3, 4, 5],
                EfiAttribute::BOOTSERVICE_ACCESS
            ),
            false
        );
        assert!(varstore.request_get(&String::from("RuntimeAccess")).is_some());

        // Delete by setting empty payload
        varstore.request_set(
            &String::from("RuntimeAccess"),
            &mut EfiVariable::new(
                vec![],
                EfiAttribute::BOOTSERVICE_ACCESS | EfiAttribute::RUNTIME_ACCESS,
            ),
            false
        );
        assert!(varstore.request_get(&String::from("RuntimeAccess")).is_none());

        // Append with 0 size payload is a no-op
        varstore.request_set(
            &String::from("BootAccess"),
            &mut EfiVariable::new(
                vec![],
                EfiAttribute::BOOTSERVICE_ACCESS,
            ),
            true
        );

        assert!(varstore.request_get(&String::from("BootAccess")).is_some());
        assert_eq!(
            varstore.request_get(&String::from("BootAccess")).unwrap().data,
            vec![2, 3, 4, 5],
        );

        varstore.bootservices_exited = true;
    
        // Cannot delete boottime accessible during runtime
        assert_eq!(varstore.variables.len(), 1);

        varstore.request_set(
            &String::from("BootAccess"),
            &mut EfiVariable::new(
                vec![],
                EfiAttribute::BOOTSERVICE_ACCESS,
            ),
            false
        );
        assert_eq!(varstore.variables.len(), 1);

    }
}
