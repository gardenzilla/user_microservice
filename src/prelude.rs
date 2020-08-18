pub enum ServiceError {
    InternalError(String),
    NotFound(String),
    AlreadyExists(String),
    BadRequest(String),
}

impl ServiceError {
    pub fn internal_error(msg: &str) -> Self {
        ServiceError::InternalError(msg.to_string())
    }
    pub fn not_found(msg: &str) -> Self {
        ServiceError::NotFound(msg.to_string())
    }
    pub fn already_exist(msg: &str) -> Self {
        ServiceError::AlreadyExists(msg.to_string())
    }
    pub fn bad_request(msg: &str) -> Self {
        ServiceError::BadRequest(msg.to_string())
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::InternalError(msg) => write!(f, "{}", msg),
            ServiceError::NotFound(msg) => write!(f, "{}", msg),
            ServiceError::AlreadyExists(msg) => write!(f, "{}", msg),
            ServiceError::BadRequest(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::fmt::Debug for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("")
            .field(&"ServiceError".to_string())
            .field(self)
            .finish()
    }
}

impl From<ServiceError> for ::tonic::Status {
    fn from(error: ServiceError) -> Self {
        match error {
            ServiceError::InternalError(msg) => ::tonic::Status::internal(msg),
            ServiceError::NotFound(msg) => ::tonic::Status::not_found(msg),
            ServiceError::AlreadyExists(msg) => ::tonic::Status::already_exists(msg),
            ServiceError::BadRequest(msg) => ::tonic::Status::invalid_argument(msg),
        }
    }
}

impl From<::storaget::PackError> for ServiceError {
    fn from(error: ::storaget::PackError) -> Self {
        ServiceError::internal_error(&error.to_string())
    }
}

pub type ServiceResult<T> = Result<T, ServiceError>;
