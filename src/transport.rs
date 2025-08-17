use core::{net::SocketAddrV4, str::FromStr};

use alloc::vec;
use anyhow::{Context, Result, anyhow, bail};
use defmt::{error, info};
use defmt_rtt as _;
use devicectrl_common::{
    DeviceId, DeviceState, DeviceStateUpdate, UpdateNotification,
    device_types::switch::SwitchState,
    protocol::simple::{DeviceBoundSimpleMessage, SIGNATURE_LEN, ServerBoundSimpleMessage},
};
use embassy_futures::select::{Either, select};
use embassy_net::{Stack, tcp::TcpSocket};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, watch::Receiver};
use embassy_time::{Duration, Timer};
use embedded_io_async::Read;
use esp_backtrace as _;
use esp_hal::{
    gpio::Output,
    peripherals::{ECC, SHA},
    rng::Rng,
};
use p256::{
    PublicKey, SecretKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};

use crate::crypto::{ecdsa_sign, ecdsa_verify};
use crate::{DEVICE_ID, PRIVATE_KEY, SERVER_PUBLIC_KEY, log_error};

#[embassy_executor::task]
pub async fn connection_task(
    stack: &'static Stack<'static>,
    power_btn_pin: &'static mut Output<'static>,
    update_receiver: &'static mut Receiver<'static, CriticalSectionRawMutex, bool, 1>,
    mut sha: SHA<'static>,
    mut ecc: ECC<'static>,
    rng: &'static mut Rng,
) {
    let secret_key = SecretKey::from_pkcs8_der(PRIVATE_KEY).expect("Failed to decode secret key");
    let server_public_key = PublicKey::from_public_key_der(SERVER_PUBLIC_KEY)
        .expect("Failed to decode server public key");

    loop {
        Timer::after(Duration::from_secs(5)).await;
        info!("Reconnecting to server...");

        if let Err(err) = open_connection(
            stack,
            power_btn_pin,
            update_receiver,
            &mut sha,
            &mut ecc,
            rng,
            &secret_key,
            &server_public_key,
        )
        .await
        {
            log_error(&err.context("Failed to handle server loop"));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_connection(
    stack: &'static Stack<'_>,
    power_btn_pin: &mut Output<'static>,
    update_receiver: &mut Receiver<'static, CriticalSectionRawMutex, bool, 1>,
    sha: &mut SHA<'_>,
    ecc: &mut ECC<'_>,
    rng: &mut Rng,
    secret_key: &SecretKey,
    server_public_key: &PublicKey,
) -> Result<()> {
    let mut rx_buffer = [0u8; 4096];
    let mut tx_buffer = [0u8; 4096];

    let mut socket = TcpSocket::new(*stack, &mut rx_buffer, &mut tx_buffer);

    socket.set_keep_alive(Some(Duration::from_secs(60)));
    socket
        .connect(SocketAddrV4::from_str(env!("SERVER_ADDR")).expect("Invalid server address"))
        .await
        .map_err(|e| anyhow!("failed to connect: {:?}", e))?;

    send_identify_message(&mut socket).await?;

    info!("Connected to server!");

    let mut current_power_state = update_receiver.get().await;

    loop {
        let mut len_buf = [0u8; size_of::<u32>()];

        // 🙏 inshallah these are cancel safe
        match select(socket.read(&mut len_buf), update_receiver.changed()).await {
            Either::First(res) => {
                if res.map_err(|err| anyhow!("size recv: {:?}", err))? != size_of::<u32>() {
                    bail!("Length delimiter is not a u32!")
                }

                handle_message(
                    &mut socket,
                    u32::from_be_bytes(len_buf) as usize,
                    power_btn_pin,
                    sha,
                    ecc,
                    rng,
                    secret_key,
                    current_power_state,
                    server_public_key,
                )
                .await?;
            }
            Either::Second(new_power_state) => {
                current_power_state = new_power_state;

                send_state_update(
                    &mut socket,
                    DeviceState::Switch(SwitchState {
                        power: current_power_state,
                    }),
                    sha,
                    ecc,
                    rng,
                    secret_key,
                )
                .await?;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_message(
    socket: &mut TcpSocket<'_>,
    message_len: usize,
    power_btn_pin: &mut Output<'static>,
    sha: &mut SHA<'_>,
    ecc: &mut ECC<'_>,
    rng: &mut Rng,
    secret_key: &SecretKey,
    current_power_state: bool,
    server_public_key: &PublicKey,
) -> Result<()> {
    let mut buf = vec![0u8; message_len];
    socket
        .read_exact(&mut buf)
        .await
        .map_err(|err| anyhow!("data recv: {:?}", err))?;

    let sig: &[u8; SIGNATURE_LEN] = &buf
        .get(..SIGNATURE_LEN)
        .context("message is not long enough for signature")?
        .try_into()?;

    let data = &buf
        .get(SIGNATURE_LEN..message_len)
        .context("message is not long enough")?;

    if !ecdsa_verify(sha, ecc, server_public_key, data, sig).context("ecdsa verification failed")? {
        bail!("signature does not match!")
    }

    let message: DeviceBoundSimpleMessage = serde_json::from_slice(data)?;
    match message {
        DeviceBoundSimpleMessage::UpdateCommand(update) => {
            if update.device_id.as_str() != DEVICE_ID {
                bail!("Update notification does not match this device id!")
            }

            update_state(power_btn_pin, current_power_state, &update.change_to).await?;
        }
        DeviceBoundSimpleMessage::StateQuery { device_id } => {
            if device_id.as_str() != DEVICE_ID {
                bail!("State query notification does not match this device id!")
            }

            send_state_update(
                socket,
                DeviceState::Switch(SwitchState {
                    power: current_power_state,
                }),
                sha,
                ecc,
                rng,
                secret_key,
            )
            .await?;
        }
        _ => error!("Unknown command received!"),
    };

    Ok(())
}

async fn update_state(
    switch_pin: &mut Output<'_>,
    current_power_state: bool,
    requested_state: &DeviceStateUpdate,
) -> Result<()> {
    let DeviceStateUpdate::Switch(new_state) = requested_state else {
        bail!("Requested state is not a switch state!")
    };

    if let Some(power) = new_state.power {
        let should_press = power != current_power_state;

        if should_press {
            info!("Triggering power update");

            switch_pin.set_high();
            Timer::after_millis(200).await;
            switch_pin.set_low();
        } else {
            info!("Not triggering power update");
        }
    }

    Ok(())
}

async fn send_state_update(
    socket: &mut TcpSocket<'_>,
    state: DeviceState,
    sha: &mut SHA<'_>,
    ecc: &mut ECC<'_>,
    rng: &mut Rng,
    secret_key: &SecretKey,
) -> Result<()> {
    let message = ServerBoundSimpleMessage::UpdateNotification(UpdateNotification {
        device_id: DeviceId::from(DEVICE_ID).map_err(|err| anyhow!(err))?,
        reachable: true,
        new_state: state,
    });

    send_message(socket, sha, ecc, rng, secret_key, &message).await
}

async fn send_identify_message(socket: &mut TcpSocket<'_>) -> Result<()> {
    let mut data = serde_json::to_vec(&ServerBoundSimpleMessage::Identify(
        DeviceId::from(DEVICE_ID).map_err(|e| anyhow!(e))?,
    ))?;

    data.splice(0..0, data.len().to_be_bytes());

    socket
        .write(&data)
        .await
        .map_err(|err| anyhow!("{:?}", err))?;

    Ok(())
}

async fn send_message(
    socket: &mut TcpSocket<'_>,
    sha: &mut SHA<'_>,
    ecc: &mut ECC<'_>,
    rng: &mut Rng,
    secret_key: &SecretKey,
    message: &ServerBoundSimpleMessage,
) -> Result<()> {
    let mut data = serde_json::to_vec(message)?;

    let sig = ecdsa_sign(sha, ecc, rng, secret_key, &data).context("ecdsa signing failed")?;

    data.splice(0..0, sig);

    data.splice(0..0, data.len().to_be_bytes());

    socket
        .write(&data)
        .await
        .map_err(|err| anyhow!("{:?}", err))?;

    Ok(())
}
