use std::{env, io, net::SocketAddr, path::PathBuf};

use crate::security::auth::{AuthConfig, env_flag};

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) bind: String,
    pub(crate) db_path: PathBuf,
    pub(crate) auth: AuthConfig,
}

impl Config {
    pub(crate) fn from_env() -> io::Result<Self> {
        let bind = env::var("MOTEHOLD_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
        let db_path = env::var("MOTEHOLD_DB")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data/motehold.sqlite"));

        let auth = AuthConfig::from_env()?;
        validate_open_bind(
            &bind,
            auth.auth_disabled,
            env_flag("MOTEHOLD_ALLOW_OPEN_BIND", false),
        )?;

        Ok(Self {
            bind,
            db_path,
            auth,
        })
    }
}

/// Refuses to serve an unauthenticated board on a non-loopback address unless
/// the operator opted in explicitly with `MOTEHOLD_ALLOW_OPEN_BIND=1`.
fn validate_open_bind(bind: &str, auth_disabled: bool, allow_open: bool) -> io::Result<()> {
    let address = bind.parse::<SocketAddr>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("MOTEHOLD_BIND must be an address:port pair: {error}"),
        )
    })?;
    if auth_disabled && !address.ip().is_loopback() && !allow_open {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "MOTEHOLD_AUTH_DISABLED is set but MOTEHOLD_BIND={bind} is not a loopback address; set MOTEHOLD_PASSWORD_HASH with MOTEHOLD_AUTH_DISABLED=0, or set MOTEHOLD_ALLOW_OPEN_BIND=1 to knowingly serve an unauthenticated board there"
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_open_bind;

    #[test]
    fn unauthenticated_non_loopback_bind_needs_explicit_opt_in() {
        assert!(validate_open_bind("127.0.0.1:8787", true, false).is_ok());
        assert!(validate_open_bind("[::1]:8787", true, false).is_ok());
        assert!(validate_open_bind("192.0.2.5:8787", false, false).is_ok());
        assert!(validate_open_bind("192.0.2.5:8787", true, false).is_err());
        assert!(validate_open_bind("0.0.0.0:8787", true, false).is_err());
        assert!(validate_open_bind("0.0.0.0:8787", true, true).is_ok());
        assert!(validate_open_bind("not-an-address", false, false).is_err());
    }
}
