
#[cfg(test)]
use balansir_common::ipc::{IpcConnection, IpcMessage, MsgType};
#[cfg(test)]
use balansir_common::{
    Action, ActionResult, DecisionTrace, DriverId, MatcherStep,
};
#[cfg(test)]
use smallvec::SmallVec;
#[cfg(test)]
use tokio::net::UnixStream;

pub mod netns;

/// Full pipeline test: Policy Decision → IPC → Executor → Result
#[tokio::test]
async fn test_full_pipeline() {
    let (daemon_stream, executor_stream) = UnixStream::pair().unwrap();
    let mut daemon_conn = IpcConnection::new(daemon_stream);
    let mut executor_conn = IpcConnection::new(executor_stream);

    let daemon_handle = tokio::spawn(async move {
        let trace = DecisionTrace {
            policy_id: 1,
            steps: SmallVec::from_slice(&[MatcherStep {
                rule_id: 1,
                matched: true,
                reason: 0,
            }]),
            action: Action::Forward {
                driver: DriverId::WIREGUARD,
            },
            execution_time_us: 42,
            correlation_id: 0,
        };

        let payload = postcard::to_allocvec(&trace).unwrap();
        let correlation_id = daemon_conn.next_correlation_id();
        let msg = IpcMessage::new(MsgType::AddRule, correlation_id, payload);
        daemon_conn.send(&msg).await.unwrap();

        let response = daemon_conn.recv().await.unwrap();
        assert_eq!(response.correlation_id, correlation_id);
        assert_eq!(response.msg_type, MsgType::ResponseOk);

        response
    });

    let executor_handle = tokio::spawn(async move {
        let request = executor_conn.recv().await.unwrap();
        assert_eq!(request.msg_type, MsgType::AddRule);

        let trace: DecisionTrace = postcard::from_bytes(&request.payload).unwrap();
        assert_eq!(
            trace.action,
            Action::Forward {
                driver: DriverId::WIREGUARD
            }
        );
        assert_eq!(trace.policy_id, 1);

        let result = ActionResult::Applied {
            execution_time_us: 100,
            rule_id: Some(1),
        };

        let response = IpcMessage::response_ok(request.correlation_id);
        executor_conn.send(&response).await.unwrap();

        (trace, result)
    });

    let (daemon_result, executor_result) = tokio::join!(daemon_handle, executor_handle);

    let daemon_response = daemon_result.unwrap();
    let (trace, _) = executor_result.unwrap();

    assert_eq!(daemon_response.msg_type, MsgType::ResponseOk);
    assert_eq!(
        trace.action,
        Action::Forward {
            driver: DriverId::WIREGUARD
        }
    );
}

/// Test concurrent requests with correlation IDs
#[tokio::test]
async fn test_concurrent_requests() {
    let (a_stream, b_stream) = UnixStream::pair().unwrap();
    let mut conn_a = IpcConnection::new(a_stream);
    let mut conn_b = IpcConnection::new(b_stream);

    let ids: Vec<u64> = (0..3).map(|_| conn_a.next_correlation_id()).collect();

    for id in &ids {
        let msg = IpcMessage::new(MsgType::HealthCheck, *id, Vec::new());
        conn_a.send(&msg).await.unwrap();
    }

    for expected_id in &ids {
        let msg = conn_b.recv().await.unwrap();
        assert_eq!(msg.correlation_id, *expected_id);

        let response = IpcMessage::response_ok(msg.correlation_id);
        conn_b.send(&response).await.unwrap();
    }

    for expected_id in &ids {
        let response = conn_a.recv().await.unwrap();
        assert_eq!(response.correlation_id, *expected_id);
        assert_eq!(response.msg_type, MsgType::ResponseOk);
    }
}

/// Test error handling
#[tokio::test]
async fn test_error_handling() {
    let (a_stream, b_stream) = UnixStream::pair().unwrap();
    let mut conn_a = IpcConnection::new(a_stream);
    let mut conn_b = IpcConnection::new(b_stream);

    let daemon_handle = tokio::spawn(async move {
        conn_a
            .request(MsgType::StartDriver, vec![1, 2, 3])
            .await
            .unwrap()
    });

    let executor_handle = tokio::spawn(async move {
        let request = conn_b.recv().await.unwrap();
        assert_eq!(request.msg_type, MsgType::StartDriver);

        let response =
            IpcMessage::response_error(request.correlation_id, "Driver not found");
        conn_b.send(&response).await.unwrap();
    });

    let (daemon_result, _) = tokio::join!(daemon_handle, executor_handle);
    let response = daemon_result.unwrap();

    assert_eq!(response.msg_type, MsgType::ResponseError);
    let error_msg = String::from_utf8(response.payload).unwrap();
    assert_eq!(error_msg, "Driver not found");
}

/// Test DriverId type safety
#[test]
fn test_driver_id_constants() {
    assert_eq!(DriverId::WIREGUARD.as_u32(), 1);
    assert_eq!(DriverId::XRAY.as_u32(), 2);
    assert_eq!(DriverId::HYSTERIA.as_u32(), 3);
    assert_eq!(DriverId::B4.as_u32(), 4);

    let custom = DriverId::new(99);
    assert_eq!(custom.as_u32(), 99);
    assert_eq!(format!("{}", custom), "Driver(99)");
}
