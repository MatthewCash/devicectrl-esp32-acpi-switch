use defmt::{info, warn};
use devicectrl_common::{
    DeviceId, DeviceState,
    device_types::switch::SwitchState,
    protocol::simple::{
        DeviceBoundSimpleMessage, ServerBoundSimpleMessage,
        esp::{TransportChannels, TransportEvent},
    },
    updates::AttributeUpdate,
};
use embassy_futures::select::{Either, select};
use embassy_time::Timer;
use esp_hal::gpio::{Input, Output};

use crate::log_error;

#[embassy_executor::task]
pub async fn app_task(
    power_led_pin: &'static mut Input<'static>,
    power_btn_pin: &'static mut Output<'static>,
    transport: &'static TransportChannels,
) {
    loop {
        match select(
            power_led_pin.wait_for_any_edge(),
            transport.incoming.receive(),
        )
        .await
        {
            // Triggered when the power LED changes state
            Either::First(_) => {
                transport
                    .outgoing
                    .send(ServerBoundSimpleMessage::UpdateNotification(
                        devicectrl_common::UpdateNotification {
                            device_id: DeviceId::from(crate::DEVICE_ID).unwrap(),
                            reachable: true,
                            new_state: DeviceState::Switch(SwitchState {
                                power: power_led_pin.is_low(),
                            }),
                        },
                    ))
                    .await;
            }
            // The following cases handle incoming transport events
            Either::Second(TransportEvent::Connected) => {
                info!("Connected to server!");

                // This isn't required, but its nice to tell the server our initial state
                transport
                    .outgoing
                    .send(ServerBoundSimpleMessage::UpdateNotification(
                        devicectrl_common::UpdateNotification {
                            device_id: DeviceId::from(crate::DEVICE_ID).unwrap(),
                            reachable: true,
                            new_state: DeviceState::Switch(SwitchState {
                                power: power_led_pin.is_low(),
                            }),
                        },
                    ))
                    .await;
            }
            Either::Second(TransportEvent::Error(err)) => {
                log_error(&err);
            }
            Either::Second(TransportEvent::Message(DeviceBoundSimpleMessage::UpdateCommand(
                update,
            ))) => {
                if update.device_id.as_str() != crate::DEVICE_ID {
                    warn!(
                        "Received update command for different device {}!",
                        update.device_id.as_str()
                    );
                    continue;
                }

                let AttributeUpdate::Power(new_state) = update.update else {
                    warn!("Received unsupported attribute update, ignoring");
                    continue;
                };

                let should_press = new_state.power != power_led_pin.is_low();

                if should_press {
                    info!("Triggering power update");

                    power_btn_pin.set_high();
                    Timer::after_millis(200).await;
                    power_btn_pin.set_low();
                } else {
                    info!("Not triggering power update");
                }
            }
            Either::Second(TransportEvent::Message(DeviceBoundSimpleMessage::StateQuery {
                device_id,
            })) => {
                if device_id.as_str() != crate::DEVICE_ID {
                    warn!(
                        "Received state query for different device {}!",
                        device_id.as_str()
                    );
                    continue;
                }

                transport
                    .outgoing
                    .send(ServerBoundSimpleMessage::UpdateNotification(
                        devicectrl_common::UpdateNotification {
                            device_id,
                            reachable: true,
                            new_state: DeviceState::Switch(SwitchState {
                                power: power_led_pin.is_low(),
                            }),
                        },
                    ))
                    .await;
            }
            _ => {}
        }
    }
}
