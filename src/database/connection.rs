//! Database Connection Management
//!
//! Utilities for managing PostgreSQL connections with SQLx.

use sqlx::PgPool;
use std::time::Duration;

/// Database connection pool type alias for convenience
pub type DatabasePool = PgPool;

/// Database configuration for connection setup
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgresql://localhost/user_service".to_string(),
            max_connections: 20,
            min_connections: 1,
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(3600),
        }
    }
}

impl DatabaseConfig {
    /// Create database configuration from environment variables
    pub fn from_env() -> Result<Self, std::env::VarError> {
        let url = std::env::var("DATABASE_URL")?;

        let max_connections = std::env::var("DB_MAX_CONNECTIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);

        let min_connections = std::env::var("DB_MIN_CONNECTIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let connect_timeout_secs = std::env::var("DB_CONNECT_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        let idle_timeout_secs = std::env::var("DB_IDLE_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(600);

        let max_lifetime_secs = std::env::var("DB_MAX_LIFETIME")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3600);

        Ok(Self {
            url,
            max_connections,
            min_connections,
            connect_timeout: Duration::from_secs(connect_timeout_secs),
            idle_timeout: Duration::from_secs(idle_timeout_secs),
            max_lifetime: Duration::from_secs(max_lifetime_secs),
        })
    }

    /// Create a database connection pool from this configuration
    pub async fn create_pool(&self) -> Result<PgPool, sqlx::Error> {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(self.max_connections)
            .min_connections(self.min_connections)
            .acquire_timeout(self.connect_timeout)
            .idle_timeout(self.idle_timeout)
            .max_lifetime(self.max_lifetime)
            .connect(&self.url)
            .await
    }
}

/// Simple pagination helper for database queries
#[derive(Debug, Clone)]
pub struct Pagination {
    pub limit: i64,
    pub offset: i64,
}

impl Pagination {
    pub fn new(page: u32, per_page: u32) -> Self {
        let per_page = per_page.clamp(1, 100) as i64;
        let page = page.max(1) as i64;
        let offset = (page - 1) * per_page;

        Self {
            limit: per_page,
            offset,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagination_creation() {
        let pagination = Pagination::new(1, 10);
        assert_eq!(pagination.limit, 10);
        assert_eq!(pagination.offset, 0);

        let pagination = Pagination::new(2, 20);
        assert_eq!(pagination.limit, 20);
        assert_eq!(pagination.offset, 20);
    }

    #[test]
    fn test_pagination_clamping() {
        let pagination = Pagination::new(1, 200); // Should clamp to 100
        assert_eq!(pagination.limit, 100);

        let pagination = Pagination::new(0, 10); // Should default to page 1
        assert_eq!(pagination.offset, 0);
    }

    #[test]
    fn test_database_config_default() {
        let config = DatabaseConfig::default();
        assert_eq!(config.max_connections, 20);
        assert_eq!(config.min_connections, 1);
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
    }
}