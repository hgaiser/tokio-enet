use std::time::{Duration, Instant};

use tokio_enet::{Event, Host, HostConfig, Packet, PacketMode};

const POLL_INTERVAL: Duration = Duration::from_millis(50);
const POLL_DEADLINE: Duration = Duration::from_secs(5);

/// Poll `host.service()` in a loop until `pred` matches an event or the deadline is reached.
async fn poll_until(host: &mut Host, pred: impl Fn(&Event) -> bool) -> Option<Event> {
    let deadline = Instant::now() + POLL_DEADLINE;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let timeout = remaining.min(POLL_INTERVAL);
        if let Some(event) = host.service(timeout).await.unwrap() {
            if pred(&event) {
                return Some(event);
            }
        }
    }
}

/// Poll `host.service()` in a loop, expecting no matching event before the short deadline.
async fn poll_expect_none(host: &mut Host, duration: Duration) {
    let deadline = Instant::now() + duration;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        let timeout = remaining.min(POLL_INTERVAL);
        let event = host.service(timeout).await.unwrap();
        assert!(event.is_none(), "expected no event, got {event:?}");
    }
}

/// Test that a client can connect to a server and exchange reliable data.
#[tokio::test]
async fn connect_and_exchange_reliable() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("tokio_enet=trace")
        .try_init();

    // Create server host.
    let server_config = HostConfig {
        address: Some("127.0.0.1:0".parse().unwrap()),
        peer_count: 4,
        channel_limit: 2,
        ..Default::default()
    };
    let mut server = Host::new(server_config).unwrap();
    let server_addr = server.local_addr().unwrap();

    // Create client host.
    let client_config = HostConfig {
        peer_count: 1,
        channel_limit: 2,
        ..Default::default()
    };
    let mut client = Host::new(client_config).unwrap();

    // Client initiates connection.
    let peer_id = client.connect(server_addr, 2, 42).unwrap();
    client.flush().await.unwrap();

    // Server receives Connect, sends ACK + VerifyConnect. No event yet (needs ACK for VerifyConnect).
    poll_expect_none(&mut server, Duration::from_millis(200)).await;

    // Client receives VerifyConnect, transitions to Connected.
    let event = poll_until(&mut client, |e| matches!(e, Event::Connect { .. })).await;
    assert!(
        matches!(&event, Some(Event::Connect { peer_id: id, .. }) if *id == peer_id),
        "expected Connect event for peer {peer_id}, got {event:?}"
    );
    // Flush ACK for VerifyConnect to server.
    client.flush().await.unwrap();

    // Server receives ACK for VerifyConnect, transitions to Connected.
    let event = poll_until(&mut server, |e| matches!(e, Event::Connect { .. })).await;
    assert!(
        matches!(&event, Some(Event::Connect { .. })),
        "expected Connect event on server, got {event:?}"
    );

    // Client sends reliable data.
    let payload = b"Hello, ENet!";
    {
        let peer = client.peer_mut(peer_id).unwrap();
        peer.send(0, Packet::new(payload, PacketMode::ReliableSequenced))
            .unwrap();
    }
    client.flush().await.unwrap();

    // Server receives the data.
    let event = poll_until(&mut server, |e| matches!(e, Event::Receive { .. })).await;
    match event {
        Some(Event::Receive {
            channel_id, packet, ..
        }) => {
            assert_eq!(channel_id, 0);
            assert_eq!(packet.data(), payload);
        }
        other => panic!("expected Receive event, got {other:?}"),
    }

    // Server sends reliable data back.
    let response = b"Hello back!";
    let server_peer_id = match server
        .peers()
        .find(|p| p.state() == tokio_enet::PeerState::Connected)
    {
        Some(p) => p.id(),
        None => panic!("no connected peer on server"),
    };
    {
        let peer = server.peer_mut(server_peer_id).unwrap();
        peer.send(0, Packet::new(response, PacketMode::ReliableSequenced))
            .unwrap();
    }
    server.flush().await.unwrap();

    // Client receives the response.
    let event = poll_until(&mut client, |e| matches!(e, Event::Receive { .. })).await;
    match event {
        Some(Event::Receive {
            channel_id, packet, ..
        }) => {
            assert_eq!(channel_id, 0);
            assert_eq!(packet.data(), response);
        }
        other => panic!("expected Receive event, got {other:?}"),
    }
}

/// Test that disconnect events are delivered.
#[tokio::test]
async fn disconnect_event() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("tokio_enet=trace")
        .try_init();

    // Set up server and client.
    let server_config = HostConfig {
        address: Some("127.0.0.1:0".parse().unwrap()),
        peer_count: 1,
        channel_limit: 1,
        ..Default::default()
    };
    let mut server = Host::new(server_config).unwrap();
    let server_addr = server.local_addr().unwrap();

    let client_config = HostConfig {
        peer_count: 1,
        channel_limit: 1,
        ..Default::default()
    };
    let mut client = Host::new(client_config).unwrap();

    // Connect.
    let peer_id = client.connect(server_addr, 1, 0).unwrap();
    client.flush().await.unwrap();

    // Server processes Connect, sends VerifyConnect.
    poll_expect_none(&mut server, Duration::from_millis(200)).await;

    // Client processes VerifyConnect, transitions to Connected.
    let event = poll_until(&mut client, |e| matches!(e, Event::Connect { .. })).await;
    assert!(event.is_some(), "expected Connect event on client");
    client.flush().await.unwrap();

    // Server receives ACK → Connected.
    let event = poll_until(&mut server, |e| matches!(e, Event::Connect { .. })).await;
    assert!(event.is_some(), "expected Connect event on server");

    // Client disconnects.
    {
        let peer = client.peer_mut(peer_id).unwrap();
        peer.disconnect(99);
    }
    client.flush().await.unwrap();

    // Server should get a disconnect event.
    let event = poll_until(&mut server, |e| {
        matches!(e, Event::Disconnect { data: 99, .. })
    })
    .await;
    assert!(
        matches!(&event, Some(Event::Disconnect { data: 99, .. })),
        "expected Disconnect event with data=99, got {event:?}"
    );
}
