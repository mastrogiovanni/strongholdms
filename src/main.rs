
use actix_web::{get, web, App, HttpServer, Result};
use iota_stronghold as stronghold;
use crypto::hashes::{blake2b::Blake2b256, Digest};
use stronghold::{
    procedures::{
        GenerateKey, KeyType, StrongholdProcedure, 
    },
    Stronghold, Location, SnapshotPath, KeyProvider
};

/// Calculates the Blake2b from a String
fn hash_blake2b(input: String) -> Vec<u8> {
    let mut hasher = Blake2b256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().to_vec()
}

fn load_from_snapshot(client_id: String, snapshot_path: String, passphrase: String) -> String {

    let client_path = client_id.as_bytes().to_vec();
    let record_path = "record_path/pippo";
    let value_path = "value_path/pluto";
    let keytype = KeyType::Ed25519;

    let stronghold = Stronghold::default();
    let snapshot_path = SnapshotPath::from_path(snapshot_path);

    let hello = String::from(passphrase);

    // calculate hash from key
    let key = hash_blake2b(hello);
    let keyprovider = KeyProvider::try_from(key).expect("Failed to load key");

    let client = stronghold
        .load_client_from_snapshot(client_path, &keyprovider, &snapshot_path)
        .expect("Could not load client from Snapshot");

    // get the public key
    let public_key_procedure = stronghold::procedures::PublicKey {
        ty: keytype.clone(),
        private_key: Location::Generic {
            record_path: record_path.as_bytes().to_vec(),
            vault_path: value_path.as_bytes().to_vec(),
        },
    };

    println!("Creating public key");
    let procedure_result = client.execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure));

    let procedure_result = procedure_result.unwrap();
    let output: Vec<u8> = procedure_result.into();

    // println!(r#"Public key is "{}" (Base64)"#, base64::encode(output));

    base64::encode(output)
}

fn save_to_snapshot(client_id: String, snapshot_path: String, passphrase: String) -> String {
    let stronghold = Stronghold::default();

    let client_path = client_id.as_bytes().to_vec();
    let record_path = "record_path/pippo";
    let value_path = "value_path/pluto";
    let keytype = KeyType::Ed25519;

    let client = stronghold
        .create_client(client_path.clone())
        .expect("Cannot creat client");

    println!("Generate key");
    let generate_key_procedure = GenerateKey {
        ty: keytype.clone(),
        output: Location::Generic {
            record_path: record_path.as_bytes().to_vec(),
            vault_path: value_path.as_bytes().to_vec(),
        },
    };

    let procedure_result = client.execute_procedure(StrongholdProcedure::GenerateKey(generate_key_procedure));

    assert!(procedure_result.is_ok());

    println!("Define the key generation procedure");
    let public_key_procedure = stronghold::procedures::PublicKey {
        ty: keytype,
        private_key: Location::Generic {
            record_path: record_path.as_bytes().to_vec(),
            vault_path: value_path.as_bytes().to_vec(),
        },
    };

    println!("Creating public key");
    let procedure_result = client.execute_procedure(StrongholdProcedure::PublicKey(public_key_procedure));

    assert!(procedure_result.is_ok());

    let procedure_result = procedure_result.unwrap();
    let output: Vec<u8> = procedure_result.into();

    // println!(r#"Public key is "{}" (Base64)"#, base64::encode(output));

    stronghold
        .write_client(client_path)
        .expect("Store client state into snapshot state failed");

    let hello = String::from(passphrase);

    let key = hash_blake2b(hello);
    
    println!(
        "Snapshot created successully? {}",
        stronghold
            .commit(&SnapshotPath::from_path(snapshot_path), &KeyProvider::try_from(key).unwrap())
            .is_ok()
    );

    base64::encode(output)
}

#[get("/load/{client_id}/{snapshot_path}/{passphrase}")]
async fn load_key(path: web::Path<(String, String, String)>) -> Result<String> {
    let (client_id, snapshot_path, passphrase) = path.into_inner();
    let public_key = load_from_snapshot(client_id, snapshot_path, passphrase);
    Ok(public_key)
}

#[get("/save/{client_id}/{snapshot_path}/{passphrase}")]
async fn save_key(path: web::Path<(String, String, String)>) -> Result<String> {
    let (client_id, snapshot_path, passphrase) = path.into_inner();
    let public_key = save_to_snapshot(client_id, snapshot_path, passphrase);
    Ok(public_key)
}

pub fn init(config: &mut web::ServiceConfig) {
    config.service(
        web::scope("")
            .service(load_key)
            .service(save_key)
    );
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .configure(init)
    })
    .bind("0.0.0.0:8000")?
    .run()
    .await
}
