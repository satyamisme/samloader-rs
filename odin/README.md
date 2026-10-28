# samloader-odin

A safe and high-performance Rust implementation of the Samsung Odin/Loke flashing protocol driver and transport manager.

This crate manages communication with Samsung devices in Download Mode (Odin protocol), providing end-to-end support for handshake negotiation, partition mapping, and firmware uploads.

## Features

- Handles the full ODIN/Loke handshake, feature negotiation, and state management.
- Requests and downloads the Partition Information Table directly from the device.
- Supports multiple backends including `nusb` (cross-platform), `rusb` (libusb), and `serialport` (VCOM).
- Processes TAR packages in-memory and streams LZ4-compressed files directly to the device.
- Simulates the stateful Loke protocol with a mock backend for offline testing.

## Usage

### Establishing a Session with a Connected Device

```rust,no_run
use samloader_odin::{
    OdinConnection, UsbBackendOption, create_backend, futures::executor::block_on,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    block_on(async {
        // 1. Establish the USB/VCOM backend connection
        let usb = create_backend(UsbBackendOption::Nusb, true).await?;
        let mut connection = OdinConnection::new(usb);

        // 2. Run the Loke protocol handshake (simple string in/out)
        connection.init().await?;

        // 3. Negotiate features and initialize an active packet session
        let mut session = connection.begin_session().await?;

        // 4. Download and print the device's PIT layout (packet I/O)
        let pit_bytes = session.receive_pit_info().await?;
        println!("PIT downloaded successfully ({} bytes).", pit_bytes.len());

        // 5. Safely end the session
        session.end_session().await?;

        Ok(())
    })
}
```

## License

This project is licensed under the Apache License, Version 2.0. The core flashing logic is a derivative work of [Grimler/Heimdall](https://git.sr.ht/~grimler/Heimdall) licensed under the MIT License.
