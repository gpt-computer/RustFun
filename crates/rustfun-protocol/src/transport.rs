//! Framed transports over any async byte stream.
//!
//! The same framing is used for stdin/stdout pipes, Unix sockets, and TCP connections: a
//! runtime adapter only has to provide a byte stream. This is what keeps the invocation
//! protocol independent of the process engine and of any language runtime.

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::codec::Codec;
use crate::error::{ProtocolError, ProtocolResult};
use crate::frame::{peek_frame_length, FrameHeader, HEADER_LEN, MAX_FRAME_BYTES};
use crate::PROTOCOL_VERSION;

/// A framed, versioned message transport.
#[derive(Debug)]
pub struct FramedTransport<S> {
    stream: S,
    read_buffer: Vec<u8>,
    max_frame_bytes: usize,
    codec: Codec,
}

impl<S> FramedTransport<S> {
    /// Wrap a stream using the default codec and frame limit.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            read_buffer: Vec::with_capacity(1024),
            max_frame_bytes: MAX_FRAME_BYTES,
            codec: Codec::default(),
        }
    }

    /// Set the default codec used for outgoing frames.
    #[must_use]
    pub fn with_codec(mut self, codec: Codec) -> Self {
        self.codec = codec;
        self
    }

    /// Set the maximum accepted frame size.
    #[must_use]
    pub fn with_max_frame_bytes(mut self, max_frame_bytes: usize) -> Self {
        self.max_frame_bytes = max_frame_bytes;
        self
    }

    /// Recover the inner stream.
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Borrow the inner stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Mutably borrow the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

impl<S> FramedTransport<S>
where
    S: AsyncRead + Unpin + AsyncWrite,
{
    /// Create a transport over a split or combined stream.
    pub fn framed(stream: S) -> Self {
        Self::new(stream)
    }

    /// Write a message frame.
    pub async fn send<T: Serialize>(&mut self, value: &T) -> ProtocolResult<()> {
        self.send_with_codec(self.codec, value).await
    }

    /// Write a message frame with an explicit codec.
    pub async fn send_with_codec<T: Serialize>(
        &mut self,
        codec: Codec,
        value: &T,
    ) -> ProtocolResult<()> {
        let frame = crate::frame::encode_frame_with_limit(codec, value, self.max_frame_bytes)?;
        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Read the next frame and return its header and body.
    pub async fn read_frame(&mut self) -> ProtocolResult<(FrameHeader, Vec<u8>)> {
        let mut body = Vec::new();
        let (header, len) = self.read_frame_into(&mut body).await?;
        Ok((header, body[..len].to_vec()))
    }

    /// Read the next frame, appending the body to `out` to allow buffer reuse.
    pub async fn read_frame_into(
        &mut self,
        out: &mut Vec<u8>,
    ) -> ProtocolResult<(FrameHeader, usize)> {
        let (header, total) = self.read_raw_frame(out).await?;
        Ok((header, total))
    }

    async fn read_raw_frame(&mut self, out: &mut Vec<u8>) -> ProtocolResult<(FrameHeader, usize)> {
        // Ensure the header is buffered.
        while self.read_buffer.len() < HEADER_LEN {
            let n = self.stream.read_buf(&mut self.read_buffer).await?;
            if n == 0 {
                return Err(ProtocolError::TransportClosed {
                    reason: "connection closed before a frame header arrived".to_owned(),
                });
            }
        }
        let (header, total) = peek_frame_length(&self.read_buffer)?.ok_or_else(|| {
            ProtocolError::TransportClosed {
                reason: "incomplete frame header".to_owned(),
            }
        })?;
        if header.version != PROTOCOL_VERSION.0 {
            return Err(ProtocolError::VersionMismatch {
                expected: PROTOCOL_VERSION.0,
                actual: header.version,
            });
        }
        if header.length > self.max_frame_bytes {
            return Err(ProtocolError::FrameTooLarge {
                length: header.length,
                limit: self.max_frame_bytes,
            });
        }
        while self.read_buffer.len() < total {
            let n = self.stream.read_buf(&mut self.read_buffer).await?;
            if n == 0 {
                return Err(ProtocolError::TransportClosed {
                    reason: format!(
                        "connection closed mid-frame: expected {total} bytes, have {}",
                        self.read_buffer.len()
                    ),
                });
            }
        }
        out.clear();
        out.extend_from_slice(&self.read_buffer[HEADER_LEN..total]);
        let consumed = total;
        self.read_buffer.drain(..consumed);
        Ok((header, out.len()))
    }

    /// Read and decode the next message.
    pub async fn recv<T: DeserializeOwned>(&mut self) -> ProtocolResult<T> {
        self.recv_into(&mut Vec::new()).await
    }

    /// Read and decode the next message, reusing `scratch` for the frame body.
    pub async fn recv_into<T: DeserializeOwned>(
        &mut self,
        scratch: &mut Vec<u8>,
    ) -> ProtocolResult<T> {
        let (header, _) = self.read_raw_frame(scratch).await?;
        header.codec.decode(scratch)
    }

    /// Send a request and await the matching response over the same transport.
    pub async fn request<Req: Serialize, Res: DeserializeOwned>(
        &mut self,
        request: &Req,
    ) -> ProtocolResult<Res> {
        self.send(request).await?;
        self.recv().await
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{InvocationRequest, InvocationResponse};
    use rustfun_model::{FunctionId, InvocationId, RequestId};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn roundtrip_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accepts");
            let mut transport = FramedTransport::new(socket);
            let request: InvocationRequest = transport.recv().await.expect("request");
            let response = InvocationResponse::success(
                request.invocation_id,
                request.function_id,
                b"{\"ok\":true}".to_vec(),
            );
            transport.send(&response).await.expect("response");
        });

        let socket = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connects");
        let mut client = FramedTransport::new(socket).with_codec(Codec::Json);
        let request = InvocationRequest::new(
            RequestId::new(),
            InvocationId::new(),
            FunctionId::new(),
            b"{}".to_vec(),
        );
        let response: InvocationResponse = client.request(&request).await.expect("response");
        assert!(response.is_success());
        assert_eq!(response.payload, b"{\"ok\":true}");
        server.await.expect("joins");
    }

    #[tokio::test]
    async fn handles_multiple_frames_on_one_connection() {
        let (mut client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let mut server = FramedTransport::new(&mut server_io);
        let mut client = FramedTransport::new(&mut client_io).with_codec(Codec::Json);

        let id = InvocationId::new();
        let function_id = FunctionId::new();
        for _ in 0..5 {
            let request = InvocationRequest::new(
                RequestId::new(),
                id.clone(),
                function_id.clone(),
                Vec::new(),
            );
            client.send(&request).await.expect("send");
            let received: InvocationRequest = server.recv().await.expect("recv");
            assert_eq!(received.invocation_id, id);
            let response = InvocationResponse::success(
                received.invocation_id,
                received.function_id,
                Vec::new(),
            );
            server.send(&response).await.expect("send response");
            let response: InvocationResponse = client.recv().await.expect("recv response");
            assert!(response.is_success());
        }
    }

    #[tokio::test]
    async fn rejects_oversized_frame_before_buffering() {
        let (mut client_io, _server_io) = tokio::io::duplex(64 * 1024);
        let mut client = FramedTransport::new(&mut client_io).with_max_frame_bytes(8);
        let err = client
            .send(&vec![0u8; 4096])
            .await
            .expect_err("must reject");
        assert_eq!(err.code(), "PROTOCOL_FRAME_TOO_LARGE");
    }

    #[tokio::test]
    async fn reports_clean_close() {
        let (client_io, server_io) = tokio::io::duplex(64);
        drop(server_io);
        let mut client = FramedTransport::new(client_io);
        let err = client
            .recv::<InvocationRequest>()
            .await
            .expect_err("closed transport");
        assert_eq!(err.code(), "PROTOCOL_TRANSPORT_CLOSED");
        assert!(err.is_retryable());
    }

    #[tokio::test]
    async fn rejects_unknown_codec_from_peer() {
        let (mut client_io, mut server_io) = tokio::io::duplex(64);
        // Hand-craft a header with an unsupported codec id.
        let mut frame = vec![b'R', b'F', b'N', b'1', 1, 9];
        frame.extend_from_slice(&4u32.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        server_io.write_all(&frame).await.expect("write");
        server_io.flush().await.expect("flush");
        let mut client = FramedTransport::new(&mut client_io);
        let err = client
            .recv::<InvocationRequest>()
            .await
            .expect_err("unknown codec");
        assert_eq!(err.code(), "PROTOCOL_UNKNOWN_CODEC");
    }
}

/// A framed, versioned *write* half of a transport.
///
/// Used when the two directions of a conversation live on different streams, which is the case
/// for child processes: stdin carries requests, stdout carries responses.
#[derive(Debug)]
pub struct FramedWriter<W> {
    stream: W,
    max_frame_bytes: usize,
    codec: Codec,
}

impl<W> FramedWriter<W> {
    /// Wrap a writer using the default codec and frame limit.
    pub fn new(stream: W) -> Self {
        Self {
            stream,
            max_frame_bytes: MAX_FRAME_BYTES,
            codec: Codec::default(),
        }
    }

    /// Set the default codec used for outgoing frames.
    #[must_use]
    pub fn with_codec(mut self, codec: Codec) -> Self {
        self.codec = codec;
        self
    }

    /// Set the maximum accepted frame size.
    #[must_use]
    pub fn with_max_frame_bytes(mut self, max_frame_bytes: usize) -> Self {
        self.max_frame_bytes = max_frame_bytes;
        self
    }

    /// Recover the inner stream.
    pub fn into_inner(self) -> W {
        self.stream
    }
}

impl<W> FramedWriter<W>
where
    W: AsyncWrite + Unpin,
{
    /// Write a message frame.
    pub async fn send<T: Serialize>(&mut self, value: &T) -> ProtocolResult<()> {
        self.send_with_codec(self.codec, value).await
    }

    /// Write a message frame with an explicit codec.
    pub async fn send_with_codec<T: Serialize>(
        &mut self,
        codec: Codec,
        value: &T,
    ) -> ProtocolResult<()> {
        let frame = crate::frame::encode_frame_with_limit(codec, value, self.max_frame_bytes)?;
        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;
        Ok(())
    }
}

/// A framed, versioned *read* half of a transport.
#[derive(Debug)]
pub struct FramedReader<R> {
    stream: R,
    read_buffer: Vec<u8>,
    max_frame_bytes: usize,
}

impl<R> FramedReader<R> {
    /// Wrap a reader using the default frame limit.
    pub fn new(stream: R) -> Self {
        Self {
            stream,
            read_buffer: Vec::with_capacity(1024),
            max_frame_bytes: MAX_FRAME_BYTES,
        }
    }

    /// Set the maximum accepted frame size.
    #[must_use]
    pub fn with_max_frame_bytes(mut self, max_frame_bytes: usize) -> Self {
        self.max_frame_bytes = max_frame_bytes;
        self
    }

    /// Recover the inner stream.
    pub fn into_inner(self) -> R {
        self.stream
    }

    /// Bytes buffered but not yet consumed.
    pub fn buffered(&self) -> &[u8] {
        &self.read_buffer
    }
}

impl<R> FramedReader<R>
where
    R: AsyncRead + Unpin,
{
    /// Read the next frame and return its header and body.
    pub async fn read_frame(&mut self) -> ProtocolResult<(FrameHeader, Vec<u8>)> {
        let mut body = Vec::new();
        let (header, len) = self.read_frame_into(&mut body).await?;
        Ok((header, body[..len].to_vec()))
    }

    /// Read the next frame, appending the body to `out` to allow buffer reuse.
    pub async fn read_frame_into(
        &mut self,
        out: &mut Vec<u8>,
    ) -> ProtocolResult<(FrameHeader, usize)> {
        while self.read_buffer.len() < HEADER_LEN {
            let n = self.stream.read_buf(&mut self.read_buffer).await?;
            if n == 0 {
                return Err(ProtocolError::TransportClosed {
                    reason: "connection closed before a frame header arrived".to_owned(),
                });
            }
        }
        let (header, total) = peek_frame_length(&self.read_buffer)?.ok_or_else(|| {
            ProtocolError::TransportClosed {
                reason: "incomplete frame header".to_owned(),
            }
        })?;
        if header.version != PROTOCOL_VERSION.0 {
            return Err(ProtocolError::VersionMismatch {
                expected: PROTOCOL_VERSION.0,
                actual: header.version,
            });
        }
        if header.length > self.max_frame_bytes {
            return Err(ProtocolError::FrameTooLarge {
                length: header.length,
                limit: self.max_frame_bytes,
            });
        }
        while self.read_buffer.len() < total {
            let n = self.stream.read_buf(&mut self.read_buffer).await?;
            if n == 0 {
                return Err(ProtocolError::TransportClosed {
                    reason: format!(
                        "connection closed mid-frame: expected {total} bytes, have {}",
                        self.read_buffer.len()
                    ),
                });
            }
        }
        out.clear();
        out.extend_from_slice(&self.read_buffer[HEADER_LEN..total]);
        let consumed = total;
        self.read_buffer.drain(..consumed);
        Ok((header, out.len()))
    }

    /// Read and decode the next message.
    pub async fn recv<T: DeserializeOwned>(&mut self) -> ProtocolResult<T> {
        self.recv_into(&mut Vec::new()).await
    }

    /// Read and decode the next message, reusing `scratch` for the frame body.
    pub async fn recv_into<T: DeserializeOwned>(
        &mut self,
        scratch: &mut Vec<u8>,
    ) -> ProtocolResult<T> {
        let (header, _) = self.read_frame_into(scratch).await?;
        header.codec.decode(scratch)
    }
}
