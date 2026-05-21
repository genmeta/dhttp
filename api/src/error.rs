use std::{error::Error, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhttpError {
    operation: String,
    message: String,
    report: String,
    causes: Vec<String>,
}

impl DhttpError {
    pub fn from_error<E>(operation: impl Into<String>, error: E) -> Self
    where
        E: Error + 'static,
    {
        let operation = operation.into();

        if let Some(error) = (&error as &dyn Error).downcast_ref::<Self>() {
            return Self {
                operation,
                message: error.message.clone(),
                report: error.report.clone(),
                causes: error.causes.clone(),
            };
        }

        let message = error.to_string();
        let report = snafu::Report::from_error(&error).to_string();
        let causes = collect_causes(&error);

        Self {
            operation,
            message,
            report,
            causes,
        }
    }

    pub fn from_message(operation: impl Into<String>, message: impl Into<String>) -> Self {
        let operation = operation.into();
        let message = message.into();
        Self {
            operation,
            report: message.clone(),
            causes: vec![message.clone()],
            message,
        }
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn report(&self) -> &str {
        &self.report
    }

    pub fn causes(&self) -> &[String] {
        &self.causes
    }
}

impl fmt::Display for DhttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed", self.operation)
    }
}

impl Error for DhttpError {}

fn collect_causes(error: &dyn Error) -> Vec<String> {
    let mut causes = vec![error.to_string()];
    let mut source = error.source();
    while let Some(error) = source {
        causes.push(error.to_string());
        source = error.source();
    }
    causes
}
