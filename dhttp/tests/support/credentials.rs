use std::{fs, path::Path, process::Command};

fn openssl(root: &Path, args: &[&str]) {
    let output = Command::new("openssl")
        .args(args)
        .current_dir(root)
        .output()
        .expect("this integration test requires OpenSSL");
    assert!(
        output.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// Generate fresh certificates and signed OCSP responses. Production verification stays enabled.
pub fn generate(root: &Path, names: &[(&str, &str)]) {
    fs::create_dir_all(root).unwrap();
    openssl(
        root,
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.crt",
            "-days",
            "2",
            "-subj",
            "/CN=DHTTP test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
        ],
    );
    for (index, &(name, hostname)) in names.iter().enumerate() {
        let serial = format!("{:02X}", index + 1);
        let directory = format!("{name}/ssl");
        fs::create_dir_all(root.join(&directory)).unwrap();
        let key = format!("{directory}/privkey.pem");
        let cert = format!("{directory}/fullchain.crt");
        let subject = format!("/CN={hostname}");
        openssl(
            root,
            &[
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-keyout",
                &key,
                "-out",
                "leaf.csr",
                "-subj",
                &subject,
            ],
        );
        fs::write(root.join("leaf.ext"), format!(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:{hostname}\n"
        )).unwrap();
        openssl(
            root,
            &[
                "x509",
                "-req",
                "-in",
                "leaf.csr",
                "-CA",
                "ca.crt",
                "-CAkey",
                "ca.key",
                "-set_serial",
                &serial,
                "-out",
                &cert,
                "-days",
                "1",
                "-extfile",
                "leaf.ext",
            ],
        );
        fs::write(
            root.join("index.txt"),
            format!("V\t491231235959Z\t\t{serial}\tunknown\t{subject}\n"),
        )
        .unwrap();
        openssl(
            root,
            &[
                "ocsp",
                "-index",
                "index.txt",
                "-rsigner",
                "ca.crt",
                "-rkey",
                "ca.key",
                "-CA",
                "ca.crt",
                "-issuer",
                "ca.crt",
                "-cert",
                &cert,
                "-respout",
                &format!("{directory}/ocsp.der"),
                "-ndays",
                "1",
            ],
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join(key), fs::Permissions::from_mode(0o400)).unwrap();
        }
    }
}
