use std::{
    fmt::Display,
    ops::ControlFlow,
    path::{Path, PathBuf},
};

use dhttp_identity::name::DhttpName;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use tokio::fs;
use toml::Spanned;

use crate::DhttpHome;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct DefaultSection {
    pub name: Option<Spanned<DhttpName<'static>>>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct DhttpSettings {
    #[serde(default)]
    pub default: DefaultSection,
}

impl DhttpSettings {
    pub const FILE_NAME: &'static str = "settings.toml";

    pub fn default_identity_name(&self) -> Option<&DhttpName<'static>> {
        self.default.name.as_ref().map(|s| s.as_ref())
    }

    pub fn set_default_identity_name(&mut self, name: DhttpName<'static>) {
        let span = match &self.default.name {
            Some(spanned) => spanned.span(),
            None => 0..0,
        };
        self.default.name = Some(Spanned::new(span, name));
    }
}

#[derive(Debug)]
pub struct DhttpSettingsFile {
    path: PathBuf,
    #[allow(dead_code)]
    content: Option<String>,
    settings: DhttpSettings,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LineCol {
    line: usize,
    column: usize,
}

impl LineCol {
    fn locate(source: &str, offset: usize) -> LineCol {
        let fold = |last: LineCol, (index, char)| {
            let current = match char {
                '\n' => LineCol {
                    line: last.line + 1,
                    column: 1,
                },
                _ => LineCol {
                    line: last.line,
                    column: last.column + 1,
                },
            };
            if index == offset {
                ControlFlow::Break(current)
            } else {
                ControlFlow::Continue(current)
            }
        };
        let (ControlFlow::Continue(line_col) | ControlFlow::Break(line_col)) =
            (source.chars().enumerate()).try_fold(LineCol { line: 1, column: 1 }, fold);
        line_col
    }
}

impl Display for LineCol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

#[derive(Debug)]
pub(crate) struct FileLineCol {
    path: PathBuf,
    line_col: LineCol,
}

impl Display for FileLineCol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.path.display(), self.line_col)
    }
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum LoadDhttpSettingsError {
    #[snafu(display("failed to read settings file {}", path.display()))]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("failed to deserialize settings file {}", path.display()))]
    Deserialize {
        path: PathBuf,
        source: toml::de::Error,
    },
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum SaveDhttpSettingsError {
    Serialize {
        path: PathBuf,
        source: toml::ser::Error,
    },
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl DhttpSettingsFile {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            content: None,
            settings: DhttpSettings::default(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn load(path: PathBuf) -> Result<Self, LoadDhttpSettingsError> {
        let source = fs::read_to_string(&path)
            .await
            .context(load_dhttp_settings_error::IoSnafu { path: &path })?;
        let settings: DhttpSettings = toml::from_str(&source)
            .context(load_dhttp_settings_error::DeserializeSnafu { path: &path })?;
        Ok(Self {
            path,
            content: Some(source),
            settings,
        })
    }

    pub fn settings(&self) -> &DhttpSettings {
        &self.settings
    }

    pub fn settings_mut(&mut self) -> &mut DhttpSettings {
        &mut self.settings
    }

    pub(crate) fn locate(&self, offset: usize) -> Option<FileLineCol> {
        let line_col = LineCol::locate(self.content.as_ref()?, offset);
        let path = self.path.clone();
        Some(FileLineCol { path, line_col })
    }

    pub async fn save(&self) -> Result<(), SaveDhttpSettingsError> {
        let source = toml::to_string_pretty(&self.settings)
            .context(save_dhttp_settings_error::SerializeSnafu { path: &self.path })?;
        fs::write(&self.path, source)
            .await
            .context(save_dhttp_settings_error::IoSnafu { path: &self.path })?;
        Ok(())
    }
}

impl DhttpHome {
    pub fn settings_path(&self) -> PathBuf {
        self.join(DhttpSettings::FILE_NAME)
    }

    pub async fn load_settings(&self) -> Result<DhttpSettingsFile, LoadDhttpSettingsError> {
        DhttpSettingsFile::load(self.settings_path()).await
    }

    pub fn new_settings(&self) -> DhttpSettingsFile {
        DhttpSettingsFile::new(self.settings_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn default_identity_round_trips_in_the_selected_home() {
        let dir = tempfile::tempdir().unwrap();
        let home = DhttpHome::new(dir.path().to_owned());
        let mut settings = home.new_settings();
        settings
            .settings_mut()
            .set_default_identity_name("alice.pilot".parse().unwrap());
        settings.save().await.unwrap();
        let loaded = home.load_settings().await.unwrap();
        assert_eq!(
            loaded.settings().default_identity_name().unwrap().as_full(),
            "alice.pilot.dhttp.net"
        );
        assert_eq!(loaded.path(), home.settings_path());
    }
}
