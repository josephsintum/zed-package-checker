//! Test support shared across modules: a genuine zip builder and a local
//! server that behaves like the bucket the advisory archives live in.

use crate::db::Database;
use futures::{SinkExt, StreamExt};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::{Service, ServiceExt};
use tower_lsp_server::jsonrpc::{Error, Id, Request, Response};
use tower_lsp_server::{Client, LanguageServer, LspService};

/// What the editor received: method and params, in order.
pub(crate) type Received = Vec<(String, Option<serde_json::Value>)>;

/// Stands in for the editor: records everything the server sends and answers
/// its requests, so the LSP layer can be exercised end to end.
pub(crate) struct FakeClient {
    received: Arc<Mutex<Received>>,
    /// When set, `window/workDoneProgress/create` is refused, as a client
    /// without progress support would.
    pub(crate) refuse_progress: Arc<AtomicBool>,
}

impl FakeClient {
    pub(crate) fn serve<S: LanguageServer>(
        init: impl FnOnce(Client) -> S,
    ) -> (LspService<S>, FakeClient) {
        let (service, socket) = LspService::new(init);
        let received = Arc::new(Mutex::new(Vec::new()));
        let refuse_progress = Arc::new(AtomicBool::new(false));
        let (received_, refuse_) = (Arc::clone(&received), Arc::clone(&refuse_progress));
        tokio::spawn(async move {
            let (mut requests, mut responses) = socket.split();
            while let Some(request) = requests.next().await {
                let (method, id, params) = request.into_parts();
                received_.lock().unwrap().push((method.to_string(), params));
                if let Some(id) = id {
                    let refused = method == "window/workDoneProgress/create"
                        && refuse_.load(Ordering::SeqCst);
                    let response = if refused {
                        Response::from_error(id, Error::method_not_found())
                    } else {
                        Response::from_ok(id, serde_json::Value::Null)
                    };
                    let _ = responses.send(response).await;
                }
            }
        });
        (
            service,
            FakeClient {
                received,
                refuse_progress,
            },
        )
    }

    /// Sends a request through the service's own router — not straight to
    /// the handler — so the server's lifecycle state is what a real editor
    /// would have produced.
    pub(crate) async fn call<S: LanguageServer>(
        service: &mut LspService<S>,
        method: &str,
        id: i64,
        params: impl serde::Serialize,
    ) -> Option<Response> {
        let request = Request::build(method.to_owned())
            .id(Id::Number(id))
            .params(serde_json::to_value(params).unwrap())
            .finish();
        service.ready().await.unwrap().call(request).await.unwrap()
    }

    pub(crate) async fn notify<S: LanguageServer>(
        service: &mut LspService<S>,
        method: &str,
        params: impl serde::Serialize,
    ) {
        let request = Request::build(method.to_owned())
            .params(serde_json::to_value(params).unwrap())
            .finish();
        let _ = service.ready().await.unwrap().call(request).await.unwrap();
    }

    pub(crate) fn count(&self, method: &str) -> usize {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m == method)
            .count()
    }

    pub(crate) fn params_of(&self, method: &str) -> Vec<serde_json::Value> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m == method)
            .filter_map(|(_, p)| p.clone())
            .collect()
    }

    /// Polls until `condition` holds over what was received, for a few
    /// seconds at most.
    pub(crate) async fn wait_until(&self, condition: impl Fn(&Received) -> bool) -> bool {
        for _ in 0..500 {
            if condition(&self.received.lock().unwrap()) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        condition(&self.received.lock().unwrap())
    }
}

/// A minimal but genuine zip, so validation exercises real archive parsing
/// rather than a stub.
pub(crate) fn fake_archive(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut cursor = io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, body) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(body.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
    }
    cursor.into_inner()
}

pub(crate) fn one_entry_archive() -> Vec<u8> {
    fake_archive(&[("GHSA-1.json", "{}")])
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut buffer = [0u8; 3];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let n = u32::from_be_bytes([0, buffer[0], buffer[1], buffer[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[derive(Clone, Copy)]
pub(crate) enum Serve {
    Archive,
    WrongChecksum,
    NotFound,
}

pub(crate) struct Served {
    pub(crate) body: Vec<u8>,
    pub(crate) etag: String,
    /// Whether a matching `If-None-Match` earns a 304.
    pub(crate) conditional: bool,
    pub(crate) delay: Duration,
    pub(crate) mode: Serve,
}

/// Serves a body the way Cloud Storage does: checksum header, ETag, and a
/// 304 for a matching validator.
pub(crate) struct ArchiveServer {
    pub(crate) host: String,
    requests: Arc<AtomicUsize>,
    not_modified: Arc<AtomicUsize>,
    served: Arc<Mutex<Served>>,
}

impl ArchiveServer {
    pub(crate) fn new(body: Vec<u8>) -> ArchiveServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let host = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let not_modified = Arc::new(AtomicUsize::new(0));
        let served = Arc::new(Mutex::new(Served {
            body,
            etag: "\"v1\"".to_owned(),
            conditional: true,
            delay: Duration::ZERO,
            mode: Serve::Archive,
        }));
        let (requests_, not_modified_, served_) =
            (requests.clone(), not_modified.clone(), served.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                requests_.fetch_add(1, Ordering::SeqCst);
                handle(stream, &served_, &not_modified_);
            }
        });
        ArchiveServer {
            host,
            requests,
            not_modified,
            served,
        }
    }

    pub(crate) fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    pub(crate) fn not_modified(&self) -> usize {
        self.not_modified.load(Ordering::SeqCst)
    }

    pub(crate) fn set(&self, f: impl FnOnce(&mut Served)) {
        f(&mut self.served.lock().unwrap());
    }

    pub(crate) fn database(&self, root: &Path) -> Database {
        Database::new(root).with_archive_host(&self.host)
    }
}

fn handle(mut stream: TcpStream, served: &Mutex<Served>, not_modified: &AtomicUsize) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut if_none_match = None;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("if-none-match")
        {
            if_none_match = Some(value.trim().to_owned());
        }
    }

    let (body, etag, conditional, delay, mode) = {
        let s = served.lock().unwrap();
        (
            s.body.clone(),
            s.etag.clone(),
            s.conditional,
            s.delay,
            s.mode,
        )
    };
    std::thread::sleep(delay);

    let response = match mode {
        Serve::NotFound => {
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngone".to_vec()
        }
        _ if conditional && if_none_match.as_deref() == Some(etag.as_str()) => {
            not_modified.fetch_add(1, Ordering::SeqCst);
            b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_vec()
        }
        Serve::Archive | Serve::WrongChecksum => {
            let sum = match mode {
                Serve::WrongChecksum => "AAAAAA==".to_owned(),
                _ => base64_encode(&crc32c::crc32c(&body).to_be_bytes()),
            };
            let mut out = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nx-goog-hash: crc32c={sum}\r\nETag: {etag}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            out.extend_from_slice(&body);
            out
        }
    };
    let _ = stream.write_all(&response);
    let _ = stream.shutdown(Shutdown::Both);
}
