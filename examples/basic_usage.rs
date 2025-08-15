//! Basic Usage Example
//!
//! This example demonstrates how to use the user service as a library
//! in your own applications.

use user_service::{CreateUserRequest, UserService, DatabaseConfig};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    // Load environment variables
    dotenv::dotenv().ok();

    // Set up database connection
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://user_service:password@localhost:5432/user_service".to_string());
    
    let config = DatabaseConfig {
        url: database_url,
        ..Default::default()
    };
    
    let pool = config.create_pool().await?;
    
    // Initialize user service
    let user_service = UserService::new(pool);
    
    // Create a new user
    let create_request = CreateUserRequest {
        name: "Alice Johnson".to_string(),
        email: "alice@example.com".to_string(),
        password: "SecurePassword123!".to_string(),
        profile_picture_url: Some("https://example.com/avatar.jpg".to_string()),
    };
    
    println!("Creating user...");
    let user = user_service.create_user(create_request).await?;
    println!("Created user: {} (ID: {})", user.name, user.id);
    
    // Verify password
    println!("Verifying password...");
    let is_valid = user_service.verify_password(user.id, "SecurePassword123!").await?;
    println!("Password verification: {}", if is_valid { "SUCCESS" } else { "FAILED" });
    
    // Get user by ID
    println!("Retrieving user by ID...");
    let retrieved_user = user_service.get_user_by_id(user.id).await?;
    println!("Retrieved user: {} <{}>", retrieved_user.name, retrieved_user.email);
    
    // Get user by email
    println!("Retrieving user by email...");
    let user_by_email = user_service.get_user_by_email(&user.email).await?;
    println!("Found user: {} (ID: {})", user_by_email.name, user_by_email.id);
    
    println!("Example completed successfully!");
    
    Ok(())
}