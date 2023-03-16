use std::usize;

use uefi::table::runtime::VariableAttributes as EfiAttributes;
use uefi::{Status as EfiStatus};

pub const DEFAULT_NAMESPACE_GUID: uefi::Guid = uefi::guid!("8be4df61-93ca-11d2-aa0d-00e098032b8c");

#[cfg(test)]
pub const TESTING_GUID: uefi::Guid = uefi::guid!("a634888c-e878-4151-aef2-54135322fd0b");

#[derive(PartialEq, Debug, Clone)]
pub struct EfiVariable {
    pub name: String,
    pub guid: uefi::Guid,
    pub data: Vec<u8>,
    pub attr: EfiAttributes,
}

impl EfiVariable {
    pub fn new(name: String, guid: uefi::Guid, data: Vec<u8>, attr: EfiAttributes) -> EfiVariable {
        EfiVariable {
            name,
            guid,
            data,
            attr,
        }
    }
}

#[derive(Debug)]
pub struct Varstore {
    variables: Vec<EfiVariable>,
    bootservices_exited: bool,
    max_data_length: usize,
    max_name_length: usize,
}

#[derive(PartialEq, Debug, Clone)]
pub enum NextResponse<'a> {
    Found(&'a EfiVariable),
    EndReached,
    Invalid,
}

impl NextResponse<'_> {
    pub fn is_found(&self) -> bool {
        matches!(*self, NextResponse::Found(_))
    }

    pub fn is_end(&self) -> bool {
        matches!(*self, NextResponse::EndReached)
    }

    pub fn is_invalid(&self) -> bool {
        matches!(*self, NextResponse::Invalid)
    }

    pub fn unwrap(&self) -> &EfiVariable {
        match *self {
            NextResponse::Found(var) => var,
            _ => panic!(),
        }
    }
}

impl Varstore {
    pub const fn new() -> Varstore {
        Varstore {
            variables: Vec::new(),
            bootservices_exited: false,
            max_name_length: 10000,
            max_data_length: 50000,
        }
    }

    pub fn with_limits(max_name: usize, max_data: usize) -> Varstore {
        Varstore {
            variables: Vec::new(),
            bootservices_exited: false,
            max_data_length: max_data,
            max_name_length: max_name,
        }
    }

    #[cfg(test)]
    pub fn insert(&mut self, var: EfiVariable) {
        self.variables.push(var);
    }

    #[cfg(test)]
    pub fn insert_new(&mut self, name: String, data: Vec<u8>, attr: EfiAttributes) {
        self.variables.push(EfiVariable {
            name: name,
            guid: TESTING_GUID,
            data: data,
            attr: attr,
        });
    }

    pub fn request_get_next(&self, name: String, guid: uefi::Guid) -> NextResponse {
        if name.is_empty() {
            if let Some(first) = self.variables.first() {
                return NextResponse::Found(first);
            }
            return NextResponse::EndReached;
        }

        let mut iter = self
            .variables
            .iter()
            .skip_while(|&k| k.name != name || k.guid != guid);

        // Current not found
        let current = iter.next();
        if current.is_none() {
            return NextResponse::Invalid;
        }

        // Next not found
        let next = iter.next();
        if let Some(next) = next {
            return NextResponse::Found(next);
        }
        NextResponse::EndReached
    }

    fn get(&self, name: &String, guid: uefi::Guid) -> Option<&EfiVariable> {
        self.variables
            .iter()
            .find(|&x| x.name == *name && x.guid == guid)
    }

    pub fn request_get(&self, name: &String, guid: uefi::Guid) -> Result<&EfiVariable, EfiStatus> {
        if name.is_empty() {
            return Err(EfiStatus::INVALID_PARAMETER);
        }

        let var = self.get(name, guid);

        if var.is_some()
            && self.bootservices_exited
            && !var.unwrap().attr.contains(EfiAttributes::RUNTIME_ACCESS)
        {
            return Err(EfiStatus::NOT_FOUND);
        }

        if var.is_none() {
            return Err(EfiStatus::NOT_FOUND);
        }

        Ok(var.unwrap())
    }

    fn get_index(&self, name: &String, guid: uefi::Guid) -> Option<usize> {
        self.variables
            .iter()
            .position(|x| *x.name == *name && x.guid == guid)
    }

    pub fn request_query_variable_info(&mut self, _attr: EfiAttributes,
        _maximum_variable_storage_size: &usize,
        _remaining_variable_storage_size: &usize,
        _maximum_variable_size: &usize) -> EfiStatus {
            EfiStatus::UNSUPPORTED
    }

    pub fn request_set(&mut self, var_in: &EfiVariable) -> Result<(), uefi::Status> {
        let mut data = var_in.clone();

        if data.name.len() > self.max_name_length {
            return Err(EfiStatus::INVALID_PARAMETER);
        }

        if data.data.len() > self.max_data_length {
            return Err(EfiStatus::INVALID_PARAMETER);
        }

        if data.attr.contains(EfiAttributes::HARDWARE_ERROR_RECORD) {
            return Err(EfiStatus::INVALID_PARAMETER);
        }

        /* Authenticated write access is deprecated and is not supported. */
        if data
            .attr
            .contains(EfiAttributes::AUTHENTICATED_WRITE_ACCESS)
        {
            return Err(EfiStatus::UNSUPPORTED);
        }

        /* Only one type of authentication may be used at a time */
        if data.attr.contains(
            EfiAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS
                | EfiAttributes::ENHANCED_AUTHENTICATED_ACCESS,
        ) {
            return Err(EfiStatus::SECURITY_VIOLATION);
        }

        /* Enhanced authenticated access is not yet implemented. */
        if data
            .attr
            .contains(EfiAttributes::ENHANCED_AUTHENTICATED_ACCESS)
        {
            return Err(EfiStatus::UNSUPPORTED);
        }

        /* Time based authenticated access is not yet implemented. */
        if data
            .attr
            .contains(EfiAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
        {
            return Err(EfiStatus::UNSUPPORTED);
        }

        /* If runtime access is set, bootservice access must also be set. */
        if data.attr.contains(EfiAttributes::RUNTIME_ACCESS)
            && !data.attr.contains(EfiAttributes::BOOTSERVICE_ACCESS)
        {
            return Err(EfiStatus::INVALID_PARAMETER);
        }

        let mut new_var = data.clone();
        let old_var = self.get(&data.name, data.guid);
        if let Some(exist) = old_var {
            if exist.attr != new_var.attr {
                return Err(EfiStatus::INVALID_PARAMETER);
            }

            if self.bootservices_exited && !new_var.attr.contains(EfiAttributes::RUNTIME_ACCESS) {
                return Err(EfiStatus::INVALID_PARAMETER);
            }

            if data.attr.contains(EfiAttributes::APPEND_WRITE) {
                data.attr.remove(EfiAttributes::APPEND_WRITE);

                let mut old_data = exist.data.clone();

                old_data.append(&mut new_var.data);
                new_var.data = old_data;

                /* Zero sized append is a no-op and not a delete */
                if new_var.data.is_empty() {
                    return Ok(());
                }

            }
            let index = self.get_index(&data.name, data.guid).unwrap();
            if new_var.data.is_empty() {
                self.variables
                    .remove(index);
                return Ok(());
            }
            self.variables[index] = data;
            return Ok(());
        }
        self.variables.push(new_var.to_owned());
        Ok(())
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

        let empty = varstore.request_get_next("".to_string(), TESTING_GUID);
        assert_eq!(empty, NextResponse::EndReached);

        let invalid = varstore.request_get_next("INVALID".to_string(), TESTING_GUID);
        assert_eq!(invalid, NextResponse::Invalid);

        varstore.insert_new(
            "Test_1".to_string(),
            vec![1, 2, 3, 4],
            EfiAttributes::BOOTSERVICE_ACCESS | EfiAttributes::RUNTIME_ACCESS,
        );
        varstore.insert_new(
            "Test_2".to_string(),
            vec![1, 2, 3, 4],
            EfiAttributes::BOOTSERVICE_ACCESS | EfiAttributes::RUNTIME_ACCESS,
        );
        varstore.insert_new(
            "Test_3".to_string(),
            vec![1, 2, 3, 4],
            EfiAttributes::BOOTSERVICE_ACCESS | EfiAttributes::RUNTIME_ACCESS,
        );
        varstore.insert_new(
            "Test_4".to_string(),
            vec![1, 2, 3, 4],
            EfiAttributes::BOOTSERVICE_ACCESS | EfiAttributes::RUNTIME_ACCESS,
        );

        let first = varstore.request_get_next("".to_string(), TESTING_GUID);
        assert!(first.is_found());

        let var = first.unwrap();
        assert_eq!(var.name.to_owned(), "Test_1".to_string());

        let next = varstore.request_get_next(var.name.to_owned(), TESTING_GUID);
        assert!(next.is_found());
        let var = next.unwrap();
        assert_eq!(var.name.to_owned(), "Test_2");

        let end = varstore.request_get_next("Test_4".to_string(), TESTING_GUID);
        assert!(end.is_end());

        let non_exist = varstore.request_get_next("Test_NonExist".to_string(), TESTING_GUID);
        assert!(non_exist.is_invalid());
    }

    #[test]
    fn get_full_access() {
        let mut varstore = Varstore::new();
        let var = EfiVariable::new(
            "TestExist".to_string(),
            TESTING_GUID,
            vec![1, 2, 3, 4],
            EfiAttributes::BOOTSERVICE_ACCESS | EfiAttributes::RUNTIME_ACCESS,
        );
        varstore.insert(var.clone());

        assert!(varstore
            .request_get(&String::from("TestExist"), TESTING_GUID)
            .is_ok());
        assert_eq!(
            varstore
                .request_get(&String::from("TestExist"), TESTING_GUID)
                .unwrap()
                .data,
            vec![1, 2, 3, 4]
        );

        assert!(varstore
            .request_get(&String::from("TestNonExist"), TESTING_GUID)
            .is_err());

        assert_eq!(
            varstore
                .request_get(&String::from("TestNonExist"), TESTING_GUID)
                .unwrap_err(),
            EfiStatus::NOT_FOUND
        );
    }

    #[test]
    fn get_runtime_access() {
        let mut varstore = Varstore::new();

        let var1 = EfiVariable::new(
            "TestBootservice".to_string(),
            TESTING_GUID,
            vec![4, 3, 2, 1],
            EfiAttributes::BOOTSERVICE_ACCESS,
        );
        varstore.insert(var1.clone());

        let var2 = EfiVariable::new(
            "TestRuntime".to_string(),
            TESTING_GUID,
            vec![4, 3, 2, 1],
            EfiAttributes::BOOTSERVICE_ACCESS | EfiAttributes::RUNTIME_ACCESS,
        );
        varstore.insert(var2.clone());

        assert!(varstore
            .request_get(&String::from("TestBootservice"), TESTING_GUID)
            .is_ok());

        varstore.bootservices_exited = true;

        assert!(varstore
            .request_get(&String::from("TestBootservice"), TESTING_GUID)
            .is_err());

        assert!(varstore
            .request_get(&String::from("TestRuntime"), TESTING_GUID)
            .is_ok());
        assert_eq!(
            varstore
                .request_get(&String::from("TestRuntime"), TESTING_GUID)
                .unwrap()
                .data,
            vec![4, 3, 2, 1]
        );
    }

    #[test]
    fn set_simple() {
        let mut varstore = Varstore::new();

        let var = EfiVariable::new(
            "Test".to_string(),
            TESTING_GUID,
            vec![1, 2, 3, 4],
            EfiAttributes::BOOTSERVICE_ACCESS,
        );

        let mut test = var.clone();
        test.name = "Test1".to_string();
        varstore.request_set(&test).unwrap();

        test = var.clone();
        test.name = "Test2".to_string();
        varstore.request_set(&test).unwrap();

        // Setting twice should not have any effect
        varstore.request_set(&test).unwrap();

        test = var.clone();
        test.name = "Test3".to_string();
        varstore.request_set(&test).unwrap();

        assert_eq!(varstore.variables.len(), 3);
    }

    #[test]
    fn set_limited() {
        let mut varstore = Varstore::with_limits(10, 10);
        let data = EfiVariable::new(
            "Test".to_string(),
            TESTING_GUID,
            vec![1, 2, 3, 4,5,6,7,8,9,10,11,12,13],
            EfiAttributes::BOOTSERVICE_ACCESS,
        );

        let name = EfiVariable::new(
            "NameIsDefintelyLongerThanTenCharacters".to_string(),
            TESTING_GUID,
            vec![1, 2, 3, 4,5,6,7,8,9,10,11,12,13],
            EfiAttributes::BOOTSERVICE_ACCESS,
        );

        let err = varstore.request_set(&name);
        assert_eq!(err, Err(EfiStatus::INVALID_PARAMETER));

        let err = varstore.request_set(&data);
        assert_eq!(err, Err(EfiStatus::INVALID_PARAMETER));

        assert_eq!(varstore.variables.len(), 0);
    }

    #[test]
    fn set_overwrite() {
        let mut varstore = Varstore::new();

        let var = EfiVariable::new(
            "Test".to_string(),
            TESTING_GUID,
            vec![1, 2, 3, 4],
            EfiAttributes::BOOTSERVICE_ACCESS,
        );

        let test = var.clone();
        varstore.request_set(&test).unwrap();

        let mut test = var.clone();
        test.data = vec![9,8,7,6];
        varstore.request_set(&test).unwrap();
        assert_eq!(varstore.variables.len(), 1);

        assert_eq!(
            varstore
                .request_get(&String::from("Test"), TESTING_GUID)
                .unwrap()
                .data,
                vec![9,8,7,6],
        );
    }


    #[test]
    fn set_delete() {
        let mut varstore = Varstore::new();

        let mut runtimeaccess_var = &mut EfiVariable::new(
            "RuntimeAccess".to_string(),
            TESTING_GUID,
            vec![1, 2, 3, 4],
            EfiAttributes::BOOTSERVICE_ACCESS | EfiAttributes::RUNTIME_ACCESS,
        );

        varstore.request_set(runtimeaccess_var).unwrap();

        assert!(varstore
            .request_get(&String::from("RuntimeAccess"), TESTING_GUID)
            .is_ok());

        // Delete by setting empty payload
        runtimeaccess_var.data = vec![];
        varstore.request_set(runtimeaccess_var).unwrap();

        assert!(varstore
            .request_get(&String::from("RuntimeAccess"), TESTING_GUID)
            .is_err());

        assert_eq!(
            varstore
                .request_get(&String::from("RuntimeAccess"), TESTING_GUID)
                .unwrap_err(),
            EfiStatus::NOT_FOUND
        );

        let mut bootaccess_var = &mut EfiVariable::new(
            "BootAccess".to_string(),
            TESTING_GUID,
            vec![2, 3, 4, 5],
            EfiAttributes::BOOTSERVICE_ACCESS,
        );

        let mut append_var = bootaccess_var.clone();
        append_var.attr.insert(EfiAttributes::APPEND_WRITE);
        // Append with 0 size payload is a no-op
        varstore.request_set(&append_var).unwrap();

        assert!(varstore
            .request_get(&String::from("BootAccess"), TESTING_GUID)
            .is_ok());
        assert_eq!(
            varstore
                .request_get(&String::from("BootAccess"), TESTING_GUID)
                .unwrap()
                .data,
            vec![2, 3, 4, 5],
        );

        varstore.bootservices_exited = true;

        // Cannot delete boottime accessible during runtime
        assert_eq!(varstore.variables.len(), 1);

        bootaccess_var.data = vec![];
        let err = varstore.request_set(bootaccess_var).unwrap_err();
        assert_eq!(err, EfiStatus::INVALID_PARAMETER);
        assert_eq!(varstore.variables.len(), 1);
    }
}
