use std::{fs, path::Path, process::Command};

fn openssl(root: &Path, args: &[&str]) {
    let executable = std::env::var_os("DHTTP_TEST_OPENSSL").unwrap_or_else(|| "openssl".into());
    let output = Command::new(executable)
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
            "-sha256",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-pkeyopt",
            "ec_param_enc:named_curve",
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
                "-sha256",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-pkeyopt",
                "ec_param_enc:named_curve",
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
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:{hostname}\nsubjectKeyIdentifier={}\n",
            format!("0:0:{:064x}", index + 1).bytes().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":")
        )).unwrap();
        openssl(
            root,
            &[
                "x509",
                "-req",
                "-sha256",
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
        // Validate actual credentials before starting QUIC. These are public
        // key files; private key bytes never appear in test output.
        openssl(root, &["pkey", "-in", &key, "-check", "-noout"]);
        openssl(
            root,
            &["pkey", "-in", &key, "-pubout", "-out", "leaf-key.pub"],
        );
        openssl(
            root,
            &[
                "x509",
                "-in",
                &cert,
                "-pubkey",
                "-noout",
                "-out",
                "leaf-cert.pub",
            ],
        );
        assert_eq!(
            fs::read(root.join("leaf-key.pub")).unwrap(),
            fs::read(root.join("leaf-cert.pub")).unwrap(),
            "certificate and private key must match for {hostname}"
        );
        openssl(
            root,
            &[
                "verify",
                "-CAfile",
                "ca.crt",
                "-verify_hostname",
                hostname,
                &cert,
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
                "-rmd",
                "sha256",
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
        openssl(
            root,
            &[
                "ocsp",
                "-respin",
                &format!("{directory}/ocsp.der"),
                "-issuer",
                "ca.crt",
                "-cert",
                &cert,
                "-CAfile",
                "ca.crt",
                "-no_nonce",
            ],
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.join(key), fs::Permissions::from_mode(0o400)).unwrap();
        }
    }
}
