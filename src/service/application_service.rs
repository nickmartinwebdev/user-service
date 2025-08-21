//! Application Service
//!
//! Service for managing multi-tenant applications and their configurations.

use bcrypt::{hash, verify, DEFAULT_COST};

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    models::application::*,
    utils::error::{AppError, AppResult},
};

/// Service for managing applications in a multi-tenant environment
#[derive(Clone)]
pub struct ApplicationService {
    pool: PgPool,
}

impl ApplicationService {
    /// Create a new application service instance
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new application with generated API credentials
    pub async fn create_application(
        &self,
        request: CreateApplicationRequest,
    ) -> AppResult<CreateApplicationResponse> {
        // Generate API credentials
        let api_key = self.generate_api_key();
        let api_secret = self.generate_api_secret();
        let api_secret_hash = hash(&api_secret, DEFAULT_COST)
            .map_err(|e| AppError::Internal(format!("Failed to hash API secret: {}", e)))?;

        // Serialize settings
        let settings_json = serde_json::to_value(&request.settings)
            .map_err(|e| AppError::Internal(format!("Failed to serialize settings: {}", e)))?;

        let app = sqlx::query!(
            r#"
            INSERT INTO applications (name, api_key, api_secret_hash, allowed_origins, settings)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, name, api_key, allowed_origins, settings, created_at
            "#,
            request.name,
            api_key,
            api_secret_hash,
            &request.allowed_origins,
            settings_json
        )
        .fetch_one(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(CreateApplicationResponse {
            id: app.id,
            name: app.name,
            api_key: app.api_key,
            api_secret, // Only returned once during creation
            allowed_origins: app.allowed_origins,
            settings: serde_json::from_value(app.settings).unwrap_or_default(),
            created_at: app.created_at.unwrap_or_else(|| chrono::Utc::now()),
        })
    }

    /// Get application by ID
    pub async fn get_application(&self, app_id: Uuid) -> AppResult<Application> {
        let row = sqlx::query!(
            "SELECT * FROM applications WHERE id = $1 AND active = true",
            app_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Application not found".to_string()))?;

        Ok(Application {
            id: row.id,
            name: row.name,
            api_key: row.api_key,
            api_secret_hash: row.api_secret_hash,
            allowed_origins: row.allowed_origins,
            settings: serde_json::from_value(row.settings).unwrap_or_default(),
            active: row.active,
            created_at: row.created_at.unwrap_or_else(|| chrono::Utc::now()),
            updated_at: row.updated_at.unwrap_or_else(|| chrono::Utc::now()),
        })
    }

    /// Authenticate application using API credentials
    pub async fn authenticate_application(
        &self,
        credentials: ApplicationCredentials,
    ) -> AppResult<Application> {
        let row = sqlx::query!(
            "SELECT * FROM applications WHERE api_key = $1 AND active = true",
            credentials.api_key
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("Invalid API key".to_string()))?;

        // Verify API secret
        if !verify(&credentials.api_secret, &row.api_secret_hash)
            .map_err(|e| AppError::Internal(format!("Failed to verify API secret: {}", e)))?
        {
            return Err(AppError::Unauthorized("Invalid API secret".to_string()));
        }

        Ok(Application {
            id: row.id,
            name: row.name,
            api_key: row.api_key,
            api_secret_hash: row.api_secret_hash,
            allowed_origins: row.allowed_origins,
            settings: serde_json::from_value(row.settings).unwrap_or_default(),
            active: row.active,
            created_at: row.created_at.unwrap_or_else(|| chrono::Utc::now()),
            updated_at: row.updated_at.unwrap_or_else(|| chrono::Utc::now()),
        })
    }

    /// Update application settings
    pub async fn update_application(
        &self,
        app_id: Uuid,
        request: UpdateApplicationRequest,
    ) -> AppResult<Application> {
        let settings_json =
            if let Some(settings) = request.settings {
                Some(serde_json::to_value(&settings).map_err(|e| {
                    AppError::Internal(format!("Failed to serialize settings: {}", e))
                })?)
            } else {
                None
            };

        let row = sqlx::query!(
            r#"
            UPDATE applications
            SET
                name = COALESCE($2, name),
                allowed_origins = COALESCE($3, allowed_origins),
                settings = COALESCE($4, settings),
                active = COALESCE($5, active),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
            app_id,
            request.name,
            request.allowed_origins.as_deref(),
            settings_json,
            request.active
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Application not found".to_string()))?;

        Ok(Application {
            id: row.id,
            name: row.name,
            api_key: row.api_key,
            api_secret_hash: row.api_secret_hash,
            allowed_origins: row.allowed_origins,
            settings: serde_json::from_value(row.settings).unwrap_or_default(),
            active: row.active,
            created_at: row.created_at.unwrap_or_else(|| chrono::Utc::now()),
            updated_at: row.updated_at.unwrap_or_else(|| chrono::Utc::now()),
        })
    }

    /// List all applications (for admin purposes)
    pub async fn list_applications(&self) -> AppResult<Vec<Application>> {
        let rows =
            sqlx::query!("SELECT * FROM applications WHERE active = true ORDER BY created_at DESC")
                .fetch_all(&self.pool)
                .await
                .map_err(AppError::Database)?;

        let applications = rows
            .into_iter()
            .map(|row| Application {
                id: row.id,
                name: row.name,
                api_key: row.api_key,
                api_secret_hash: row.api_secret_hash,
                allowed_origins: row.allowed_origins,
                settings: serde_json::from_value(row.settings).unwrap_or_default(),
                active: row.active,
                created_at: row.created_at.unwrap_or_else(|| chrono::Utc::now()),
                updated_at: row.updated_at.unwrap_or_else(|| chrono::Utc::now()),
            })
            .collect();

        Ok(applications)
    }

    /// Rotate API credentials for an application
    pub async fn rotate_credentials(&self, app_id: Uuid) -> AppResult<(String, String)> {
        let api_key = self.generate_api_key();
        let api_secret = self.generate_api_secret();
        let api_secret_hash = hash(&api_secret, DEFAULT_COST)
            .map_err(|e| AppError::Internal(format!("Failed to hash API secret: {}", e)))?;

        sqlx::query!(
            r#"
            UPDATE applications
            SET api_key = $2, api_secret_hash = $3, updated_at = NOW()
            WHERE id = $1 AND active = true
            "#,
            app_id,
            api_key,
            api_secret_hash
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok((api_key, api_secret))
    }

    /// Deactivate an application
    pub async fn deactivate_application(&self, app_id: Uuid) -> AppResult<()> {
        let result = sqlx::query!(
            "UPDATE applications SET active = false, updated_at = NOW() WHERE id = $1",
            app_id
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::Database)?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Application not found".to_string()));
        }

        Ok(())
    }

    /// Get application usage statistics
    pub async fn get_application_stats(&self, app_id: Uuid) -> AppResult<ApplicationStats> {
        let stats = sqlx::query!(
            r#"
            SELECT
                (SELECT COUNT(*) FROM users WHERE application_id = $1) as total_users,
                (SELECT COUNT(DISTINCT user_id) FROM auth_audit_log
                 WHERE application_id = $1 AND created_at > NOW() - INTERVAL '24 hours') as active_users_24h,
                (SELECT COUNT(*) FROM auth_audit_log
                 WHERE application_id = $1 AND created_at > NOW() - INTERVAL '24 hours') as auth_events_24h,
                (SELECT COUNT(*) FROM auth_audit_log
                 WHERE application_id = $1 AND success = false AND created_at > NOW() - INTERVAL '24 hours') as failed_auth_events_24h
            "#,
            app_id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(AppError::Database)?;

        Ok(ApplicationStats {
            total_users: stats.total_users.unwrap_or(0),
            active_users_24h: stats.active_users_24h.unwrap_or(0),
            auth_events_24h: stats.auth_events_24h.unwrap_or(0),
            failed_auth_events_24h: stats.failed_auth_events_24h.unwrap_or(0),
        })
    }

    /// Generate a random API key
    fn generate_api_key(&self) -> String {
        format!(
            "ak_{}",
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect::<String>()
                .to_lowercase()
        )
    }

    /// Generate a random API secret
    fn generate_api_secret(&self) -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect::<String>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    #[sqlx::test]
    async fn test_create_application(pool: PgPool) {
        let app_service = ApplicationService::new(pool);

        let request = CreateApplicationRequest {
            name: "Test App".to_string(),
            allowed_origins: vec!["https://example.com".to_string()],
            settings: ApplicationSettings::default(),
        };

        let result = app_service.create_application(request).await;
        assert!(result.is_ok());

        let app = result.unwrap();
        assert_eq!(app.name, "Test App");
        assert!(app.api_key.starts_with("ak_"));
        assert_eq!(app.allowed_origins, vec!["https://example.com"]);
    }

    #[sqlx::test]
    async fn test_authenticate_application(pool: PgPool) {
        let app_service = ApplicationService::new(pool);

        // First create an application
        let request = CreateApplicationRequest {
            name: "Auth Test App".to_string(),
            allowed_origins: vec!["https://test.com".to_string()],
            settings: ApplicationSettings::default(),
        };

        let created_app = app_service.create_application(request).await.unwrap();

        // Now test authentication
        let credentials = ApplicationCredentials {
            api_key: created_app.api_key.clone(),
            api_secret: created_app.api_secret.clone(),
        };

        let auth_result = app_service.authenticate_application(credentials).await;
        assert!(auth_result.is_ok());

        let authenticated_app = auth_result.unwrap();
        assert_eq!(authenticated_app.id, created_app.id);
        assert_eq!(authenticated_app.name, created_app.name);
    }

    #[sqlx::test]
    async fn test_authenticate_application_invalid_credentials(pool: PgPool) {
        let app_service = ApplicationService::new(pool);

        let credentials = ApplicationCredentials {
            api_key: "invalid_key".to_string(),
            api_secret: "invalid_secret".to_string(),
        };

        let result = app_service.authenticate_application(credentials).await;
        assert!(result.is_err());

        if let Err(AppError::Unauthorized(_)) = result {
            // Expected error type
        } else {
            panic!("Expected Unauthorized error");
        }
    }
}
