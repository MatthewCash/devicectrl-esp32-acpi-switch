#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::ToString;
use anyhow::Error;
use defmt::{error, info, println};
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_net::{Runner, Stack, StackResources, StaticConfigV4};
use embassy_sync::{
    blocking_mutex::raw::CriticalSectionRawMutex,
    watch::{Receiver, Sender, Watch},
};
use embassy_time::{Duration, Timer};
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    ecc::Ecc,
    gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull},
    peripherals,
    rng::{Rng, Trng},
    sha::Sha,
    timer::timg::TimerGroup,
};
use esp_hal_embassy::main;
use esp_wifi::{EspWifiController, wifi::WifiDevice};
use esp32_ecdsa::CryptoContext;
use heapless::Vec;
use p256::{
    PublicKey, SecretKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use transport::connection_task;
use wifi::wifi_connection;

mod transport;
mod wifi;

const DEVICE_ID: &str = env!("DEVICE_ID");

macro_rules! mk_static {
    ($t:ty,$val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write(($val));
        x
    }};
}

pub fn log_error(err: &Error) {
    error!("Error: {}", err.to_string().as_str());
    println!("Caused by:");

    err.chain().skip(1).enumerate().for_each(|(i, cause)| {
        println!("   {}: {}", i, cause.to_string().as_str());
    })
}

pub const SERVER_PUBLIC_KEY: &[u8] = include_bytes!(env!("SERVER_PUBLIC_KEY_PATH"));
pub const PRIVATE_KEY: &[u8] = include_bytes!(env!("PRIVATE_KEY_PATH"));

#[main]
async fn main(spawner: Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::_80MHz));

    esp_alloc::heap_allocator!(size: 72 * 1024);

    let mut rng = Rng::new(peripherals.RNG);

    let timer1 = TimerGroup::new(peripherals.TIMG1);
    esp_hal_embassy::init(timer1.timer0);

    // enable internal antenna
    Output::new(peripherals.GPIO3, Level::Low, OutputConfig::default());
    Timer::after(Duration::from_millis(100)).await;
    Output::new(peripherals.GPIO14, Level::Low, OutputConfig::default());

    let timer0 = TimerGroup::new(peripherals.TIMG0);
    let wifi_init = &*mk_static!(
        EspWifiController<'static>,
        esp_wifi::init(timer0.timer0, rng).unwrap()
    );

    let (controller, interfaces) = esp_wifi::wifi::new(wifi_init, peripherals.WIFI).unwrap();

    let config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: env!("IP_CIDR").parse().unwrap(),
        gateway: None,
        dns_servers: Vec::new(),
    });

    let seed = (rng.random() as u64) << 32 | rng.random() as u64;

    let (stack, runner) = embassy_net::new(
        interfaces.sta,
        config,
        mk_static!(StackResources<3>, StackResources::<3>::new()),
        seed,
    );

    let stack = mk_static!(Stack<'_>, stack);
    let runner = mk_static!(Runner<'_, WifiDevice<'_>>, runner);

    let crypto = CryptoContext {
        sha: Sha::new(peripherals.SHA),
        ecc: Ecc::new(peripherals.ECC),
        trng: Trng::new(unsafe { peripherals::RNG::steal() }, peripherals.ADC1), // should be safe as we don't use RNG after this
        secret_key: SecretKey::from_pkcs8_der(PRIVATE_KEY).expect("Failed to decode secret key"),
        server_public_key: PublicKey::from_public_key_der(SERVER_PUBLIC_KEY)
            .expect("Failed to decode server public key"),
    };

    let power_btn_pin = &mut *mk_static!(
        Output<'_>,
        Output::new(peripherals.GPIO20, Level::Low, OutputConfig::default())
    );
    let power_led_pin = &mut *mk_static!(
        Input<'_>,
        Input::new(
            peripherals.GPIO19,
            InputConfig::default().with_pull(Pull::Up)
        )
    );
    let case_led_pin = &mut *mk_static!(
        Output<'_>,
        Output::new(peripherals.GPIO18, Level::Low, OutputConfig::default())
    );

    let update_channel = &*mk_static!(Watch<CriticalSectionRawMutex
        , bool, 1>, Watch::new());
    let update_sender = &*mk_static!(
        Sender<'_, CriticalSectionRawMutex, bool, 1>,
        update_channel.sender()
    );
    let update_receiver = &mut *mk_static!(
        Receiver<'_, CriticalSectionRawMutex, bool, 1>,
        update_channel.receiver().unwrap()
    );

    spawner.spawn(wifi_connection(controller)).unwrap();
    spawner.spawn(net_task(runner)).unwrap();
    spawner
        .spawn(connection_task(
            stack,
            power_btn_pin,
            update_receiver,
            crypto,
        ))
        .unwrap();
    spawner
        .spawn(case_led_monitor(power_led_pin, case_led_pin, update_sender))
        .unwrap();
}

#[embassy_executor::task]
async fn net_task(runner: &'static mut Runner<'static, WifiDevice<'static>>) {
    runner.run().await
}

#[embassy_executor::task]
async fn case_led_monitor(
    power_led_pin: &'static mut Input<'static>,
    case_led_pin: &'static mut Output<'static>,
    update_sender: &'static Sender<'static, CriticalSectionRawMutex, bool, 1>,
) {
    update_sender.send(power_led_pin.is_low());

    loop {
        power_led_pin.wait_for_any_edge().await;

        update_sender.send(power_led_pin.is_low());

        info!("Triggering case led power button press");

        case_led_pin.set_high();
        Timer::after_millis(200).await;
        case_led_pin.set_low();
    }
}
