//! API Client Example
//!
//! This example shows how to interact with the user service HTTP API
//! using a simple HTTP client.

use reqwest::Client;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let base_url = "http://localhost:3000";

    // Health check
    println!("Checking service health...");
    let health_response = client.get(&format!("{}/health", base_url)).send().await?;

    if health_response.status().is_success() {
        let health_data: serde_json::Value = health_response.json().await?;
        println!("Service is healthy: {}", health_data);
    } else {
        println!("Service health check failed: {}", health_response.status());
        return Ok(());
    }

    // Create a new user
    println!("\nCreating a new user...");
    let user_data = json!({
        "name": "Bob Smith",
        "email": "bob@example.com",
        "password": "MySecurePassword123!",
        "profile_picture_url": "https://example.com/bob-avatar.jpg"
    });

    let create_response = client
        .post(&format!("{}/users", base_url))
        .json(&user_data)
        .send()
        .await?;

    if !create_response.status().is_success() {
        println!("Failed to create user: {}", create_response.status());
        let error_text = create_response.text().await?;
        println!("Error: {}", error_text);
        return Ok(());
    }

    let create_result: serde_json::Value = create_response.json().await?;
    let user_id = create_result["data"]["id"].as_str().unwrap();
    println!("Created user with ID: {}", user_id);

    // Get the user
    println!("\nRetrieving user...");
    let get_response = client
        .get(&format!("{}/users/{}", base_url, user_id))
        .send()
        .await?;

    if get_response.status().is_success() {
        let user_data: serde_json::Value = get_response.json().await?;
        println!("Retrieved user: {}", user_data);
    } else {
        println!("Failed to retrieve user: {}", get_response.status());
    }

    // Update user
    println!("\nUpdating user...");
    let update_data = json!({
        "name": "Robert Smith",
        "profile_picture_url": "https://example.com/robert-new-avatar.jpg"
    });

    let update_response = client
        .put(&format!("{}/users/{}", base_url, user_id))
        .json(&update_data)
        .send()
        .await?;

    if update_response.status().is_success() {
        let updated_user: serde_json::Value = update_response.json().await?;
        println!("Updated user: {}", updated_user);
    } else {
        println!("Failed to update user: {}", update_response.status());
    }

    // Verify password
    println!("\nVerifying password...");
    let verify_data = json!({
        "password": "MySecurePassword123!"
    });

    let verify_response = client
        .post(&format!("{}/users/{}/verify-password", base_url, user_id))
        .json(&verify_data)
        .send()
        .await?;

    if verify_response.status().is_success() {
        let verify_result: serde_json::Value = verify_response.json().await?;
        let is_valid = verify_result["data"]["valid"].as_bool().unwrap_or(false);
        println!(
            "Password verification: {}",
            if is_valid { "SUCCESS" } else { "FAILED" }
        );
    } else {
        println!("Failed to verify password: {}", verify_response.status());
    }

    println!("\nAPI client example completed!");

    Ok(())
}
