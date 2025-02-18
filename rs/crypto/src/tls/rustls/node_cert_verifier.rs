use crate::tls::tls_cert_from_registry;
use ic_crypto_tls_cert_validation::ValidTlsCertificate;
use ic_crypto_tls_interfaces::{SomeOrAllNodes, TlsPublicKeyCert};
use ic_crypto_utils_tls::{
    node_id_from_cert_subject_common_name, tls_pubkey_cert_from_rustls_certs,
};
use ic_interfaces_registry::RegistryClient;
use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
use ic_types::{NodeId, RegistryVersion};
use std::{sync::Arc, time::SystemTime};
use tokio_rustls::rustls::{
    client::{ServerCertVerified, ServerCertVerifier},
    server::{ClientCertVerified, ClientCertVerifier},
    Certificate, DistinguishedName, Error as TLSError, ServerName,
};

#[cfg(test)]
mod tests;

/// Implements `ServerCertVerifier`. The peer
/// certificate is considered trusted if the following conditions hold:
/// * No intermediate certificates.
/// * The end entitiy certificate can be parsed from DER.
/// * The end entity certificate subject CN can be parsed as a `NodeId`.
/// * The `NodeId` parsed from the end entity's subject CN is
///   contained in `allowed_nodes` (as passed to `new`).
/// * The end entity certificate equals the node's certificate fetched from the
///   `registry_client` at version `registry_version` for the `NodeId` parsed
///   from the end entity certificate. (The `registry_client` and
///   `registry_version` are passed to `new`.)
///
/// If any of these conditions does not hold, a `TLSError` is returned.
pub struct NodeServerCertVerifier {
    allowed_nodes: SomeOrAllNodes,
    registry_client: Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
}

impl NodeServerCertVerifier {
    /// Creates a verifier that considers only certificates for the
    /// `allowed_nodes` fetched from the `registry_client` at registry version
    /// `registry_version` as trusted.
    pub fn new(
        allowed_nodes: SomeOrAllNodes,
        registry_client: Arc<dyn RegistryClient>,
        registry_version: RegistryVersion,
    ) -> Self {
        Self {
            allowed_nodes,
            registry_client,
            registry_version,
        }
    }
}

/// Implements `ClientCertVerifier`. The peer
/// certificate is considered trusted if the following conditions hold:
/// * No intermediate certificates.
/// * The end entitiy certificate can be parsed from DER.
/// * The end entity certificate subject CN can be parsed as a `NodeId`.
/// * The `NodeId` parsed from the end entity's subject CN is
///   contained in `allowed_nodes` (as passed to the constructors).
/// * The end entity certificate equals the node's certificate fetched from the
///   `registry_client` at version `registry_version` for the `NodeId` parsed
///   from the end entity certificate. (The `registry_client` and
///   `registry_version` are passed to the constructors.)
///
/// If any of these conditions does not hold, a `TLSError` is returned.
///
/// This verifier always offers client authentication, see `offer_client_auth`.
pub struct NodeClientCertVerifier {
    allowed_nodes: SomeOrAllNodes,
    registry_client: Arc<dyn RegistryClient>,
    registry_version: RegistryVersion,
}

impl NodeClientCertVerifier {
    /// Creates a verifier that considers only certificates for the
    /// `allowed_nodes` fetched from the `registry_client` at registry version
    /// `registry_version` as trusted.
    ///
    /// Client authentication is mandatory.
    pub fn new_with_mandatory_client_auth(
        allowed_nodes: SomeOrAllNodes,
        registry_client: Arc<dyn RegistryClient>,
        registry_version: RegistryVersion,
    ) -> Self {
        Self {
            allowed_nodes,
            registry_client,
            registry_version,
        }
    }
}

impl ServerCertVerifier for NodeServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, TLSError> {
        verify_node_cert(
            end_entity,
            intermediates,
            &self.allowed_nodes,
            self.registry_client.as_ref(),
            self.registry_version,
        )
        .map(|_| ServerCertVerified::assertion())
    }
}

impl ClientCertVerifier for NodeClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        _now: SystemTime,
    ) -> Result<ClientCertVerified, TLSError> {
        verify_node_cert(
            end_entity,
            intermediates,
            &self.allowed_nodes,
            self.registry_client.as_ref(),
            self.registry_version,
        )
        .map(|()| ClientCertVerified::assertion())
    }
}

fn verify_node_cert(
    end_entity_der: &Certificate,
    intermediates: &[Certificate],
    allowed_nodes: &SomeOrAllNodes,
    registry_client: &dyn RegistryClient,
    registry_version: RegistryVersion,
) -> Result<(), TLSError> {
    ensure_intermediate_certs_empty(intermediates)?;
    let end_entity = tls_pubkey_cert_from_rustls_certs(std::slice::from_ref(end_entity_der))?;
    let end_entity_node_id = node_id_from_cert_subject_common_name(&end_entity).map_err(|e| {
        TLSError::General(format!(
            "The presented certificate subject CN could not be parsed as node ID: {:?}",
            e
        ))
    })?;
    ensure_node_id_in_allowed_nodes(end_entity_node_id, allowed_nodes)?;
    let node_cert_from_registry =
        node_cert_from_registry(end_entity_node_id, registry_client, registry_version)?;
    ensure_certificates_equal(end_entity, end_entity_node_id, node_cert_from_registry)?;
    // It's important to do the validity check after checking equality to the
    // registry cert because the cert validation uses a different parser
    // (`x509_parser` as opposed to OpenSSL that is used above) and it is safer
    // to not just pass any untrusted data to it. We consider the DER here trusted
    // because it is equal to the certificate DER stored in the registry, as checked
    // above.
    ensure_node_certificate_is_valid(end_entity_der.0.clone(), end_entity_node_id)?;
    Ok(())
}

fn ensure_intermediate_certs_empty(intermediates: &[Certificate]) -> Result<(), TLSError> {
    if !intermediates.is_empty() {
        return Err(TLSError::General(format!(
            "The peer must send exactly one self signed certificate, but it sent {} certificates.",
            intermediates.len() + 1
        )));
    }
    Ok(())
}

fn ensure_node_id_in_allowed_nodes(
    node_id: NodeId,
    allowed_nodes: &SomeOrAllNodes,
) -> Result<(), TLSError> {
    if !allowed_nodes.contains(node_id) {
        return Err(TLSError::General(format!(
            "The peer certificate with node ID {} is not allowed. Allowed node IDs: {:?}",
            node_id, allowed_nodes
        )));
    }
    Ok(())
}

fn node_cert_from_registry(
    node_id: NodeId,
    registry_client: &dyn RegistryClient,
    registry_version: RegistryVersion,
) -> Result<TlsPublicKeyCert, TLSError> {
    tls_cert_from_registry(registry_client, node_id, registry_version).map_err(|e| {
        TLSError::General(format!(
            "Failed to retrieve TLS certificate for node ID {} from the registry at registry version {}: {:?}",
            node_id, registry_version, e
        ))
    })
}

fn ensure_certificates_equal(
    end_entity_cert: TlsPublicKeyCert,
    node_id: NodeId,
    node_cert_from_registry: TlsPublicKeyCert,
) -> Result<(), TLSError> {
    if node_cert_from_registry != end_entity_cert {
        return Err(TLSError::General(
            format!("The peer certificate is not trusted since it differs from the registry certificate. NodeId of presented cert: {}", node_id),
        ));
    }
    Ok(())
}

fn ensure_node_certificate_is_valid(
    certificate_der: Vec<u8>,
    cert_node_id: NodeId,
) -> Result<(), TLSError> {
    ValidTlsCertificate::try_from((X509PublicKeyCert { certificate_der }, cert_node_id))
        .map_err(|e| TLSError::General(format!("The peer certificate is invalid: {}", e)))?;
    Ok(())
}
