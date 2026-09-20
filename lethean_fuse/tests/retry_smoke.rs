use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use lethean_fuse_lib::api::ApiClient;

fn force_reset(stream: TcpStream) {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let linger = libc::linger { l_onoff: 1, l_linger: 0 };
        unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            );
        }
    }
    drop(stream);
}

fn respond_ok_empty_list(mut stream: TcpStream) {
    let mut buf = [0u8; 4096];
    let _ = stream.read(&mut buf);
    let body = b"[]";
    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

#[test]
fn list_files_recovers_from_connection_reset() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_srv = attempts.clone();

    let server = thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let n = attempts_srv.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                force_reset(stream);
            } else {
                respond_ok_empty_list(stream);
                break;
            }
        }
    });

    let mut api = ApiClient::new(format!("http://{addr}")).expect("client");
    api.set_vault_id(Some("test-vault".to_string()));

    let result = api.list_files(0, Some(200));
    server.join().unwrap();

    assert!(result.is_ok(), "expected list_files to recover from transient resets, got: {:?}", result.err());
    assert_eq!(result.unwrap().len(), 0);
    assert!(attempts.load(Ordering::SeqCst) >= 3, "server should have seen at least 3 attempts (2 resets + 1 success)");
}