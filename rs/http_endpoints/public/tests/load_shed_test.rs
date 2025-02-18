pub mod common;

use crate::common::{
    basic_consensus_pool_cache, basic_registry_client, basic_state_manager_mock,
    default_get_latest_state, default_latest_certified_height, default_read_certified_state,
    get_free_localhost_socket_addr, start_http_endpoint, wait_for_status_healthy,
};
use async_trait::async_trait;
use hyper::{Body, Client, Method, Request, StatusCode};
use ic_agent::{
    agent::{http_transport::ReqwestHttpReplicaV2Transport, QueryBuilder},
    agent_error::HttpErrorPayload,
    export::Principal,
    hash_tree::Label,
    Agent, AgentError,
};
use ic_config::http_handler::Config;
use ic_interfaces_state_manager_mocks::MockStateManager;
use ic_pprof::{Error, Pprof, PprofCollector};
use ic_types::messages::{Blob, HttpQueryResponse, HttpQueryResponseReply};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{runtime::Runtime, sync::Notify};

/// Test concurrency limiter for `/query` endpoint and that when the load shedder kicks in
/// we return 429.
#[test]
fn test_load_shedding_query() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();

    let config = Config {
        listen_addr: addr,
        max_query_concurrent_requests: 1,
        ..Default::default()
    };

    let mock_state_manager = basic_state_manager_mock();
    let mock_consensus_cache = basic_consensus_pool_cache();
    let mock_registry_client = basic_registry_client();

    let canister = Principal::from_text("223xb-saaaa-aaaaf-arlqa-cai").unwrap();

    let (_, _, mut query_handler) = start_http_endpoint(
        rt.handle().clone(),
        config,
        Arc::new(mock_state_manager),
        Arc::new(mock_consensus_cache),
        Arc::new(mock_registry_client),
        Arc::new(Pprof::default()),
    );

    let query_exec_running = Arc::new(Notify::new());
    let load_shedder_returned = Arc::new(Notify::new());

    let ok_agent = Agent::builder()
        .with_transport(ReqwestHttpReplicaV2Transport::create(format!("http://{}", addr)).unwrap())
        .build()
        .unwrap();

    let query = QueryBuilder::new(&ok_agent, canister, "test".to_string())
        .with_effective_canister_id(canister)
        .sign()
        .unwrap();

    let agent_clone = ok_agent.clone();
    let query_clone = query.clone();
    let load_shedder_returned_clone = load_shedder_returned.clone();
    let query_exec_running_clone = query_exec_running.clone();

    // This agent's request wil be load shedded.
    let load_shedded_agent = rt.spawn(async move {
        query_exec_running_clone.notified().await;

        let resp = agent_clone
            .query_signed(
                query_clone.effective_canister_id,
                query_clone.signed_query.clone(),
            )
            .await;

        load_shedder_returned_clone.notify_one();

        resp
    });

    // Mock query exec service
    rt.spawn(async move {
        let (_, resp) = query_handler.next_request().await.unwrap();
        query_exec_running.notify_one();
        load_shedder_returned.notified().await;

        resp.send_response(HttpQueryResponse::Replied {
            reply: HttpQueryResponseReply {
                arg: Blob("success".into()),
            },
        })
    });

    rt.block_on(async {
        wait_for_status_healthy(&ok_agent).await.unwrap();

        let resp = ok_agent
            .query_signed(query.effective_canister_id, query.signed_query.clone())
            .await;

        assert!(resp.is_ok(), "Received unexpeceted response: {:?}", resp);

        let resp = load_shedded_agent.await.unwrap();
        let expected_resp = StatusCode::TOO_MANY_REQUESTS;

        match resp {
            Err(AgentError::HttpError(HttpErrorPayload { status, .. })) => {
                assert_eq!(expected_resp, status)
            }
            _ => panic!(
                "Load shedder did not kick in. Received unexpeceted response: {:?}",
                resp
            ),
        }
    });
}

/// Test concurrency limiter for `/read_state` endpoint and that when the load shedder kicks in
/// we return 429.
/// Test scenario:
/// 1. Set the read state concurrency limiter to 1.
/// 2. We make two concurrent polls. We expect the last poll request to hit the load shedder.
#[test]
fn test_load_shedding_read_state() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();

    let config = Config {
        listen_addr: addr,
        max_read_state_concurrent_requests: 1,
        ..Default::default()
    };

    let read_state_running = Arc::new(Notify::new());
    let load_shedder_returned = Arc::new(Notify::new());

    let load_shedder_returned_clone = load_shedder_returned.clone();
    let read_state_running_clone = read_state_running.clone();

    let service_is_healthy = Arc::new(AtomicBool::new(false));
    let service_is_healthy_clone = service_is_healthy.clone();

    let mut mock_state_manager = MockStateManager::new();

    mock_state_manager
        .expect_get_latest_state()
        .returning(default_get_latest_state);

    mock_state_manager
        .expect_latest_certified_height()
        .returning(default_latest_certified_height);

    let rt_clone: tokio::runtime::Handle = rt.handle().clone();
    mock_state_manager
        .expect_read_certified_state()
        .returning(move |labeled_tree| {
            // Need this check, otherwise wait_for_status_healthy() will be stuck.
            // This is due to status endpoint also relying on state_reader_executor.
            if service_is_healthy_clone.load(Ordering::Relaxed) {
                rt_clone.block_on(async {
                    read_state_running.notify_one();
                    load_shedder_returned.notified().await;
                })
            }
            default_read_certified_state(labeled_tree)
        });

    let mock_consensus_cache = basic_consensus_pool_cache();
    let mock_registry_client = basic_registry_client();

    let canister = Principal::from_text("223xb-saaaa-aaaaf-arlqa-cai").unwrap();

    let _ = start_http_endpoint(
        rt.handle().clone(),
        config,
        Arc::new(mock_state_manager),
        Arc::new(mock_consensus_cache),
        Arc::new(mock_registry_client),
        Arc::new(Pprof::default()),
    );

    let ok_agent = Agent::builder()
        .with_transport(ReqwestHttpReplicaV2Transport::create(format!("http://{}", addr)).unwrap())
        .build()
        .unwrap();
    let load_shedded_agent = ok_agent.clone();

    let paths: Vec<Vec<Label<Vec<u8>>>> = vec![vec!["time".into()]];
    let paths_clone = paths.clone();

    // This agent's request wil be load shedded
    let load_shedded_agent_resp = rt.spawn(async move {
        read_state_running_clone.notified().await;

        let response = load_shedded_agent
            .read_state_raw(paths_clone, canister)
            .await;

        load_shedder_returned_clone.notify_one();

        response.map(|_| ())
    });

    rt.block_on(async {
        wait_for_status_healthy(&ok_agent).await.unwrap();
        service_is_healthy.store(true, Ordering::Relaxed);

        let response = ok_agent.read_state_raw(paths, canister).await;

        // first request should not hit load shedder
        assert!(
            !(matches!(response, Err(AgentError::HttpError(HttpErrorPayload { status, .. })) if StatusCode::TOO_MANY_REQUESTS == status
            )),
            "Load shedder kicked in. Received unexpeceted response: {:?}", response
        );

        let response = load_shedded_agent_resp.await.unwrap();

        // second request should hit load shedder
        assert!(
            matches!(response, Err(AgentError::HttpError(HttpErrorPayload { status, .. })) if StatusCode::TOO_MANY_REQUESTS == status
            ),
            "Load shedder did not kick in. Received unexpeceted response: {:?}", response
        );
    });
}

/// Test concurrency limiter for `/_/pprof` endpoints, and that when the load shedder kicks in
/// we return 429.
/// Test scenario:
/// 1. Set the concurrency limiter for pprof services, `max_pprof_concurrent_requests`, to 1.
/// 2. Make 1 get request to `/_/pprof` where we wait before responding.
/// 3. Make requests to endpoints under `/_/prof` expecting them all to be load shedded.
/// 4. Return a response for the first request and ssert it does not get load shedded.
#[test]
fn test_load_shedding_pprof() {
    // We have to create this custom MockPprof, as the `MockAll` crate
    // doesn't support async closures in `returning()` yet.
    // See: https://github.com/MystenLabs/sui/issues/5155
    struct MockPprof {
        buffer_filled: Arc<Notify>,
        load_shedded_responses_finished: Arc<Notify>,
    }
    impl MockPprof {
        pub fn new(
            buffer_filled: Arc<Notify>,
            load_shedded_responses_finished: Arc<Notify>,
        ) -> Self {
            Self {
                buffer_filled,
                load_shedded_responses_finished,
            }
        }
    }
    #[async_trait]
    impl PprofCollector for MockPprof {
        async fn profile(&self, _: Duration, _: i32) -> Result<Vec<u8>, Error> {
            Ok(Vec::new())
        }
        async fn flamegraph(&self, _: Duration, _: i32) -> Result<Vec<u8>, Error> {
            self.buffer_filled.notify_one();
            self.load_shedded_responses_finished.notified().await;
            Ok(Vec::new())
        }
    }

    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();

    let buffer_size = 1;

    let config = Config {
        listen_addr: addr,
        max_pprof_concurrent_requests: buffer_size,
        ..Default::default()
    };

    let buffer_filled = Arc::new(Notify::new());
    let load_shedded_responses_finished = Arc::new(Notify::new());

    let mock_pprof = MockPprof::new(
        buffer_filled.clone(),
        load_shedded_responses_finished.clone(),
    );

    let mock_state_manager = basic_state_manager_mock();
    let mock_consensus_cache = basic_consensus_pool_cache();
    let mock_registry_client = basic_registry_client();

    let _ = start_http_endpoint(
        rt.handle().clone(),
        config,
        Arc::new(mock_state_manager),
        Arc::new(mock_consensus_cache),
        Arc::new(mock_registry_client),
        Arc::new(mock_pprof),
    );

    let flame_graph_req = move || {
        Request::builder()
            .method(Method::GET)
            .uri(format!("http://{}/_/pprof/{}", addr, "flamegraph"))
            .body(Body::empty())
            .expect("request builder")
    };

    let profile_req = move || {
        Request::builder()
            .method(Method::GET)
            .uri(format!("http://{}/_/pprof/{}", addr, "profile"))
            .body(Body::empty())
            .expect("request builder")
    };

    let pprof_base_req = move || {
        Request::builder()
            .method(Method::GET)
            .uri(format!("http://{}/_/pprof", addr))
            .body(Body::empty())
            .expect("request builder")
    };

    // This request wil fill the load shedder.
    let ok_request = rt.spawn(async move {
        let client = Client::new();
        let response = client.request(flame_graph_req()).await.unwrap();
        response.status()
    });

    rt.block_on(async {
        let requests: Vec<Box<dyn Fn() -> Request<Body>>> = vec![
            Box::new(flame_graph_req),
            Box::new(pprof_base_req),
            Box::new(profile_req),
        ];

        buffer_filled.notified().await;

        for request_builder in requests {
            let client = Client::new();
            let response = client.request(request_builder()).await.unwrap();

            assert_eq!(StatusCode::TOO_MANY_REQUESTS, response.status());
        }

        load_shedded_responses_finished.notify_one();

        assert_eq!(StatusCode::OK, ok_request.await.unwrap())
    });
}

/// Test concurrency limiter for `/call` endpoint and that when the load shedder kicks in
/// we return 429.
/// Test scenario:
/// 1. Set the concurrency limiter for the call service, `max_call_concurrent_requests`, to 1.
/// 2. Use [`Agent`]  to make an update calls where we wait with responding for the update call
/// inside the ingress filter service handle.
/// 3. Concurrently make another update call, and assert it hits the load shedder.
#[test]
fn test_load_shedding_update_call() {
    let rt = Runtime::new().unwrap();
    let addr = get_free_localhost_socket_addr();

    let config = Config {
        listen_addr: addr,
        max_call_concurrent_requests: 1,
        ..Default::default()
    };

    let mock_state_manager = basic_state_manager_mock();
    let mock_consensus_cache = basic_consensus_pool_cache();
    let mock_registry_client = basic_registry_client();

    let canister = Principal::from_text("223xb-saaaa-aaaaf-arlqa-cai").unwrap();

    let (mut ingress_filter, mut ingress_sender, _) = start_http_endpoint(
        rt.handle().clone(),
        config,
        Arc::new(mock_state_manager),
        Arc::new(mock_consensus_cache),
        Arc::new(mock_registry_client),
        Arc::new(Pprof::default()),
    );

    let ingress_filter_running = Arc::new(Notify::new());
    let load_shedder_returned = Arc::new(Notify::new());

    let ok_agent = Agent::builder()
        .with_transport(ReqwestHttpReplicaV2Transport::create(format!("http://{}", addr)).unwrap())
        .build()
        .unwrap();

    let load_shedded_agent = ok_agent.clone();

    let ingress_filter_running_clone = ingress_filter_running.clone();
    let load_shedder_returned_clone = load_shedder_returned.clone();

    let load_shedded_agent_handle = rt.spawn(async move {
        ingress_filter_running_clone.notified().await;
        let resp = load_shedded_agent
            .update(&canister, "some method")
            .call()
            .await;
        load_shedder_returned_clone.notify_one();
        resp
    });

    // Ingress sender mock that returns empty Ok(()) response.
    rt.spawn(async move {
        loop {
            let (_, resp) = ingress_sender.next_request().await.unwrap();
            resp.send_response(Ok(()))
        }
    });

    // Mock ingress filter
    rt.spawn(async move {
        let (_, resp) = ingress_filter.next_request().await.unwrap();
        ingress_filter_running.notify_one();
        load_shedder_returned.notified().await;
        resp.send_response(Ok(()))
    });

    rt.block_on(async {
        wait_for_status_healthy(&ok_agent).await.unwrap();
        let resp = ok_agent.update(&canister, "some method").call().await;

        assert!(resp.is_ok(), "Received unexpeceted response: {:?}", resp);

        let resp = load_shedded_agent_handle.await.unwrap();
        let expected_resp = StatusCode::TOO_MANY_REQUESTS;

        match resp {
            Err(AgentError::HttpError(HttpErrorPayload { status, .. })) => {
                assert_eq!(expected_resp, status)
            }
            _ => panic!(
                "Load shedder did not kick in. Received unexpeceted response: {:?}",
                resp
            ),
        }
    });
}
