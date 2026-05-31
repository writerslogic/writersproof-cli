// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

pub mod rbac;
pub mod secure_channel;
#[cfg(unix)]
pub mod unix_socket;

mod async_client;
pub mod crypto;
pub(crate) mod messages;
mod server;
mod server_handler;
mod server_windows;
mod sync_client;

#[cfg(test)]
mod tests;

pub use async_client::{AsyncIpcClient, AsyncIpcClientError};
pub use messages::{IpcErrorCode, IpcMessage, IpcMessageHandler};
pub use rbac::{required_role, IpcRole};
pub use server::IpcServer;
pub(crate) use sync_client::IpcClient;
