//! gRPC service descriptors (`GrpcProtoDescriptorStore`): `FileDescriptorSet`s uploaded over the control plane or
//! read from `grpcDescriptorDirectory`, kept as the services they declare. Only the protobuf wire format of the
//! descriptor messages is decoded; a set that does not parse, or whose methods name message types no file in it
//! declares, is refused as `Descriptors.FileDescriptor.buildFrom` refuses it.

use parking_lot::Mutex;
use serde_json::{Value, json};

#[derive(Debug, Clone)]
pub struct Method {
    pub name: String,
    pub input_type: String,
    pub output_type: String,
    pub client_streaming: bool,
    pub server_streaming: bool,
}

#[derive(Debug, Clone)]
pub struct Service {
    pub full_name: String,
    pub methods: Vec<Method>,
}

#[derive(Default)]
pub struct Descriptors {
    /// By full name, in the order they were first loaded; a later load replaces a service in place.
    services: Mutex<Vec<Service>>,
    /// The message and enum types of every set loaded.
    pool: Mutex<std::sync::Arc<crate::protobuf::Pool>>,
    /// Every `FileDescriptorProto` loaded, by name (a later load replaces a file), for server reflection.
    files: Mutex<Vec<File>>,
}

/// A loaded `FileDescriptorProto`: its bytes, dependencies and top-level symbols.
#[derive(Debug, Clone)]
pub struct File {
    pub name: String,
    pub bytes: Vec<u8>,
    pub dependencies: Vec<String>,
    /// Top-level messages, enums and services, fully qualified.
    pub symbols: Vec<String>,
    pub services: Vec<String>,
}

/// Why a descriptor set was refused (`GrpcException`'s message).
pub const LOAD_FAILED: &str = "Failed to load proto descriptor set";

impl Descriptors {
    pub fn load(&self, bytes: &[u8]) -> Result<(), String> {
        let services = parse_set(bytes).ok_or_else(|| LOAD_FAILED.to_string())?;
        let mut pool = crate::protobuf::Pool::clone(&self.pool.lock());
        pool.add_set(bytes).map_err(|_| LOAD_FAILED.to_string())?;
        *self.pool.lock() = std::sync::Arc::new(pool);
        let mut files = self.files.lock();
        for file in parse_files(bytes).unwrap_or_default() {
            match files.iter_mut().find(|f| f.name == file.name) {
                Some(existing) => *existing = file,
                None => files.push(file),
            }
        }
        drop(files);
        let mut current = self.services.lock();
        for service in services {
            match current.iter_mut().find(|s| s.full_name == service.full_name) {
                Some(existing) => *existing = service,
                None => current.push(service),
            }
        }
        Ok(())
    }

    /// `loadDescriptorDirectory`: every `*.dsc` and `*.desc` file; one that fails is skipped.
    pub fn load_directory(&self, directory: &std::path::Path) -> Vec<(String, String)> {
        let mut failures = Vec::new();
        let Ok(entries) = std::fs::read_dir(directory) else { return failures };
        let mut paths: Vec<std::path::PathBuf> =
            entries.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|x| x == "dsc" || x == "desc")).collect();
        paths.sort();
        for path in paths {
            let loaded = std::fs::read(&path).map_err(|e| e.to_string()).and_then(|bytes| self.load(&bytes).map_err(|_| format!("Failed to load proto descriptor set from {}", path.display())));
            if let Err(e) = loaded {
                failures.push((path.display().to_string(), e));
            }
        }
        failures
    }

    pub fn clear(&self) {
        self.services.lock().clear();
        *self.pool.lock() = Default::default();
        self.files.lock().clear();
    }

    /// The loaded files.
    pub fn files(&self) -> Vec<File> {
        self.files.lock().clone()
    }

    /// Service names in the order `services_json` lists them.
    pub fn service_names(&self) -> Vec<String> {
        let services = self.services.lock();
        let names: Vec<String> = services.iter().map(|s| s.full_name.clone()).collect();
        crate::recorded::java_hashmap_order(&names).into_iter().map(|i| names[i].clone()).collect()
    }

    pub fn has_services(&self) -> bool {
        !self.services.lock().is_empty()
    }

    /// `getMethod`: the method `service/method` declares.
    pub fn method(&self, service: &str, method: &str) -> Option<Method> {
        self.services.lock().iter().find(|s| s.full_name == service).and_then(|s| s.methods.iter().find(|m| m.name == method).cloned())
    }

    /// A snapshot of the types, for encoding and decoding messages.
    pub fn pool(&self) -> std::sync::Arc<crate::protobuf::Pool> {
        self.pool.lock().clone()
    }

    /// `PUT /mockserver/grpc/services`: services in `ConcurrentHashMap` iteration order, each with its methods.
    pub fn services_json(&self) -> Value {
        let services = self.services.lock();
        let names: Vec<String> = services.iter().map(|s| s.full_name.clone()).collect();
        let order = crate::recorded::java_hashmap_order(&names);
        Value::Array(
            order
                .into_iter()
                .map(|i| {
                    let s = &services[i];
                    json!({
                        "name": s.full_name,
                        "methods": s.methods.iter().map(|m| json!({
                            "name": m.name,
                            "inputType": m.input_type,
                            "outputType": m.output_type,
                            "clientStreaming": m.client_streaming,
                            "serverStreaming": m.server_streaming,
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect(),
        )
    }
}

/// A protobuf message's fields: `(number, value)` where a length-delimited value is its bytes and a varint its value.
enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed,
}

fn varint(buf: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *buf.get(*at)?;
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn fields(buf: &[u8]) -> Option<Vec<(u64, Field<'_>)>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < buf.len() {
        let key = varint(buf, &mut at)?;
        let (number, wire) = (key >> 3, key & 0x7);
        if number == 0 {
            return None;
        }
        let field = match wire {
            0 => Field::Varint(varint(buf, &mut at)?),
            1 => {
                at = at.checked_add(8).filter(|a| *a <= buf.len())?;
                Field::Fixed
            }
            2 => {
                let len = usize::try_from(varint(buf, &mut at)?).ok()?;
                let end = at.checked_add(len).filter(|e| *e <= buf.len())?;
                let bytes = &buf[at..end];
                at = end;
                Field::Bytes(bytes)
            }
            5 => {
                at = at.checked_add(4).filter(|a| *a <= buf.len())?;
                Field::Fixed
            }
            _ => return None,
        };
        out.push((number, field));
    }
    Some(out)
}

fn text(field: &Field) -> Option<String> {
    match field {
        Field::Bytes(b) => std::str::from_utf8(b).ok().map(str::to_string),
        _ => None,
    }
}

/// `DescriptorProto`'s full names, nested types included.
fn message_names(message: &[u8], scope: &str, out: &mut Vec<String>) -> Option<()> {
    let fields = fields(message)?;
    let name = fields.iter().find(|(n, _)| *n == 1).and_then(|(_, f)| text(f)).unwrap_or_default();
    let full = if scope.is_empty() { name } else { format!("{scope}.{name}") };
    for (number, field) in &fields {
        if let (3, Field::Bytes(nested)) = (number, field) {
            message_names(nested, &full, out)?;
        }
    }
    out.push(full);
    Some(())
}

/// The services of a `FileDescriptorSet`, `None` when it does not parse or a method's type is not declared.
fn parse_set(bytes: &[u8]) -> Option<Vec<Service>> {
    let mut messages = Vec::new();
    let mut services = Vec::new();
    for (number, file) in fields(bytes)? {
        let (1, Field::Bytes(file)) = (number, file) else { continue };
        let file = fields(file)?;
        let package = file.iter().find(|(n, _)| *n == 2).and_then(|(_, f)| text(f)).unwrap_or_default();
        for (number, field) in &file {
            match (number, field) {
                (4, Field::Bytes(message)) => message_names(message, &package, &mut messages)?,
                (6, Field::Bytes(service)) => {
                    let service = fields(service)?;
                    let name = service.iter().find(|(n, _)| *n == 1).and_then(|(_, f)| text(f)).unwrap_or_default();
                    let mut methods = Vec::new();
                    for (number, method) in &service {
                        let (2, Field::Bytes(method)) = (number, method) else { continue };
                        let method = fields(method)?;
                        let get = |n: u64| method.iter().find(|(k, _)| *k == n).map(|(_, f)| f);
                        let flag = |n: u64| matches!(get(n), Some(Field::Varint(v)) if *v != 0);
                        let type_name = |n: u64| get(n).and_then(text).map(|t| t.trim_start_matches('.').to_string()).unwrap_or_default();
                        methods.push(Method {
                            name: get(1).and_then(text).unwrap_or_default(),
                            input_type: type_name(2),
                            output_type: type_name(3),
                            client_streaming: flag(5),
                            server_streaming: flag(6),
                        });
                    }
                    let full_name = if package.is_empty() { name } else { format!("{package}.{name}") };
                    services.push(Service { full_name, methods });
                }
                _ => {}
            }
        }
    }
    let declared = |t: &str| messages.iter().any(|m| m == t) || t.starts_with("google.protobuf.");
    services.iter().flat_map(|s| &s.methods).all(|m| declared(&m.input_type) && declared(&m.output_type)).then_some(services)
}

/// The files of a `FileDescriptorSet` with what reflection needs of each.
fn parse_files(bytes: &[u8]) -> Option<Vec<File>> {
    let mut out = Vec::new();
    for (number, file) in fields(bytes)? {
        let (1, Field::Bytes(raw)) = (number, file) else { continue };
        let parsed = fields(raw)?;
        let package = parsed.iter().find(|(n, _)| *n == 2).and_then(|(_, f)| text(f)).unwrap_or_default();
        let qualify = |name: String| if package.is_empty() { name } else { format!("{package}.{name}") };
        let mut file = File {
            name: parsed.iter().find(|(n, _)| *n == 1).and_then(|(_, f)| text(f)).unwrap_or_default(),
            bytes: raw.to_vec(),
            dependencies: Vec::new(),
            symbols: Vec::new(),
            services: Vec::new(),
        };
        for (number, field) in &parsed {
            match (number, field) {
                (3, f) => file.dependencies.extend(text(f)),
                (4 | 5, Field::Bytes(b)) => {
                    let name = fields(b)?.iter().find(|(n, _)| *n == 1).and_then(|(_, f)| text(f)).unwrap_or_default();
                    file.symbols.push(qualify(name));
                }
                (6, Field::Bytes(b)) => {
                    let name = fields(b)?.iter().find(|(n, _)| *n == 1).and_then(|(_, f)| text(f)).unwrap_or_default();
                    file.services.push(qualify(name));
                }
                _ => {}
            }
        }
        out.push(file);
    }
    Some(out)
}

