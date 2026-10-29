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

### Flashing Firmware

Flashing happens in three phases: configuring a `FlashRequest` performs no I/O, `prepare` reads and validates the inputs without a device, and `execute` flashes the device.

```rust,no_run
use samloader_odin::{
    FlashRequest, OdinConnection, UsbBackendOption, create_backend,
    futures::{executor::block_on, io::AllowStdIo},
};
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    block_on(async {
        // 1. Configure the flash
        let ap = AllowStdIo::new(File::open("AP.tar.md5")?);
        let request = FlashRequest::new().packages([("AP.tar.md5", ap)]);

        // 2. Verify and index the inputs before connecting to a device
        let prepared = request.prepare().await?;
        if prepared.flashes_userdata() {
            println!("This will wipe the device's data.");
        }

        // 3. Connect to the device and flash
        let usb = create_backend(UsbBackendOption::Nusb, true).await?;
        let mut connection = OdinConnection::new(usb);
        connection.init().await?;
        let mut session = connection.begin_session().await?;
        prepared.execute(&mut session).await?;

        Ok(())
    })
}
```

## WebAssembly

The `nusb` backend supports `wasm32-unknown-unknown` in browsers with [WebUSB](https://wicg.github.io/webusb/) support (Chromium-based browsers). The `rusb` and `serialport` backends are not available on WebAssembly.

`web-sys` considers its WebUSB bindings unstable and [requires the root crate to opt in](https://wasm-bindgen.github.io/wasm-bindgen/web-sys/unstable-apis.html). This flag is not inherited from dependencies, so put the following in the `.cargo/config.toml` of the project building the final WebAssembly binary, otherwise `nusb` fails to compile:

```toml
[target.wasm32-unknown-unknown]
rustflags = ["--cfg=web_sys_unstable_apis"]
```

Browsers only expose USB devices the user has granted access to. Before connecting, call `request_device` (or `request_reboot_device` before `reboot_download`) from a user gesture such as a click handler to prompt for permission.

## License

This project is licensed under the Apache License, Version 2.0. The core flashing logic is a derivative work of [Grimler/Heimdall](https://git.sr.ht/~grimler/Heimdall) licensed under the MIT License.
