//! A wrapper to control Windows audio device and per-application volume and
//! mute status.

#![warn(missing_docs)]

use crossbeam_channel::{unbounded, Receiver};
use windows::{Abi, Guid, Interface};

use bindings::Windows::Win32::Foundation::{CloseHandle, HINSTANCE, PSTR, PWSTR};
use bindings::Windows::Win32::Media::Audio::CoreAudio::{
    eAll, eMultimedia, eRender, IAudioEndpointVolume, IAudioEndpointVolumeCallback,
    IAudioSessionControl2, IAudioSessionEvents, IAudioSessionManager2, IAudioSessionNotification,
    IMMDevice, IMMDeviceEnumerator, IMMNotificationClient, ISimpleAudioVolume, MMDeviceEnumerator,
    DEVICE_STATE_ACTIVE,
};
use bindings::Windows::Win32::Storage::StructuredStorage::{
    PropVariantClear, PROPVARIANT, STGM_READ,
};
use bindings::Windows::Win32::System::Com::CLSCTX_ALL;
use bindings::Windows::Win32::System::PropertiesSystem::PropVariantToString;
use bindings::Windows::Win32::System::{
    ProcessStatus::{K32GetModuleBaseNameW, K32GetModuleFileNameExA},
    Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
};

pub mod events;

lazy_static::lazy_static! {
    static ref DEVICE_GUID: Guid = Guid::from("a45c254e-df1c-4efd-8020-67d146a850e0");
}

/// Common methods to control the volume of a device or session.
///
/// Floats must be in the 0.0 to 1.0 range.
pub trait VolumeControl {
    /// Get the current volume.
    fn get_volume(&mut self) -> windows::Result<f32>;
    /// Set a new volume.
    fn set_volume(&mut self, level: f32) -> windows::Result<()>;

    /// Get if it is currently muted.
    fn get_mute(&mut self) -> windows::Result<bool>;
    /// Set if muted.
    fn set_mute(&mut self, mute: bool) -> windows::Result<()>;
}

/// A physical audio device.
#[derive(Debug)]
pub struct AudioDevice {
    device: IMMDevice,
    audio_endpoint_volume: Option<IAudioEndpointVolume>,

    /// A friendly name for the device, as defined by the operating system, if
    /// one exists.
    pub friendly_name: Option<String>,
}

impl AudioDevice {
    /// Get all of the active audio devices.
    ///
    /// This will exclude unplugged and disabled devices.
    pub fn active_devices() -> windows::Result<Vec<AudioDevice>> {
        unsafe {
            let device_enumerator: IMMDeviceEnumerator =
                windows::create_instance(&MMDeviceEnumerator)?;
            let devices = device_enumerator.EnumAudioEndpoints(eAll, DEVICE_STATE_ACTIVE)?;

            let device_count = devices.GetCount()?;
            tracing::debug!(device_count, "got number of active audio devices");

            let mut audio_devices = Vec::with_capacity(device_count as usize);

            for device_idx in 0..device_count {
                tracing::debug!(device_idx, "getting audio device");
                let device = devices.Item(device_idx)?;

                let properties = device.OpenPropertyStore(STGM_READ as u32)?;
                let property_count = properties.GetCount()?;

                let mut friendly_name: Option<String> = None;

                for property_idx in 0..property_count {
                    let property_key = properties.GetAt(property_idx)?;
                    tracing::trace!(
                        "looking at property {:?} {}",
                        property_key.fmtid,
                        property_key.pid
                    );

                    if property_key.fmtid == *DEVICE_GUID && property_key.pid == 14 {
                        let property_value = properties.GetValue(&property_key)?;

                        let mut buf = [0u16; 1024];
                        let psz = PWSTR(buf.as_mut_ptr());
                        let cch = buf.len() as u32;

                        PropVariantToString(&property_value, psz, cch)?;

                        let name = pwstr_to_string(psz);
                        tracing::debug!("found device friendly name: {}", name);
                        friendly_name = Some(name);

                        PropVariantClear(&property_value as *const _ as *mut PROPVARIANT)?;

                        break;
                    }
                }

                audio_devices.push(AudioDevice {
                    device,
                    friendly_name,

                    audio_endpoint_volume: None,
                });
            }

            Ok(audio_devices)
        }
    }

    /// Get notifications for changes in connected devices.
    pub fn notifications(
    ) -> windows::Result<(IMMNotificationClient, Receiver<events::DeviceNotification>)> {
        let (tx, rx) = unbounded();

        let device_notifications = events::DeviceNotifications::new(tx);

        unsafe {
            let device_enumerator: IMMDeviceEnumerator =
                windows::create_instance(&MMDeviceEnumerator)?;

            device_enumerator.RegisterEndpointNotificationCallback(device_notifications.clone())?;
        }

        Ok((device_notifications, rx))
    }

    /// Activate the device volume control interface on demand, and keep a
    /// reference for future use.
    fn audio_endpoint_volume(&mut self) -> windows::Result<&IAudioEndpointVolume> {
        if let Some(ref audio_endpoint_volume) = self.audio_endpoint_volume {
            tracing::trace!("already had device IAudioEndpointVolume");
            return Ok(audio_endpoint_volume);
        }

        tracing::debug!("activating device IAudioEndpointVolume");
        let mut audio_endpoint_volume = None;
        unsafe {
            self.device.Activate(
                &IAudioEndpointVolume::IID,
                CLSCTX_ALL.0,
                std::ptr::null_mut(),
                audio_endpoint_volume.set_abi(),
            )
        }?;
        self.audio_endpoint_volume = audio_endpoint_volume;

        Ok(self.audio_endpoint_volume.as_ref().unwrap())
    }

    /// Register for events on device changes.
    pub fn events(
        &mut self,
    ) -> windows::Result<(IAudioEndpointVolumeCallback, Receiver<events::DeviceEvent>)> {
        let (tx, rx) = unbounded();

        let audio_endpoint_volume = self.audio_endpoint_volume()?;

        let session_events = events::DeviceEvents::new(tx);

        unsafe {
            audio_endpoint_volume.RegisterControlChangeNotify(session_events.clone())?;
        }

        Ok((session_events, rx))
    }
}

impl VolumeControl for AudioDevice {
    fn get_volume(&mut self) -> windows::Result<f32> {
        let audio_endpoint_volume = self.audio_endpoint_volume()?;

        unsafe { audio_endpoint_volume.GetMasterVolumeLevelScalar() }
    }

    fn set_volume(&mut self, level: f32) -> windows::Result<()> {
        let audio_endpoint_volume = self.audio_endpoint_volume()?;

        unsafe { audio_endpoint_volume.SetMasterVolumeLevelScalar(level, std::ptr::null()) }
    }

    fn get_mute(&mut self) -> windows::Result<bool> {
        let audio_endpoint_volume = self.audio_endpoint_volume()?;

        unsafe { audio_endpoint_volume.GetMute() }.map(Into::into)
    }

    fn set_mute(&mut self, mute: bool) -> windows::Result<()> {
        let audio_endpoint_volume = self.audio_endpoint_volume()?;

        unsafe { audio_endpoint_volume.SetMute(mute, std::ptr::null()) }
    }
}

/// A manager for the system's audio sessions.
pub struct AudioSessionManager {
    manager: IAudioSessionManager2,
}

impl AudioSessionManager {
    /// Create a new session manager.
    ///
    /// It is possible for this to not be able to get an instance.
    pub fn new() -> windows::Result<Option<Self>> {
        let manager = unsafe {
            tracing::trace!("creating IMMDeviceEnumerator");
            let device_enumerator: IMMDeviceEnumerator =
                windows::create_instance(&MMDeviceEnumerator)?;
            tracing::trace!("getting default audio endpoint");
            let default_audio_endpoint =
                device_enumerator.GetDefaultAudioEndpoint(eRender, eMultimedia)?;

            tracing::trace!("activating IAudioSessionManager2");
            let mut manager = None;
            default_audio_endpoint.Activate(
                &IAudioSessionManager2::IID,
                CLSCTX_ALL.0,
                std::ptr::null_mut(),
                manager.set_abi(),
            )?;

            manager
        };

        Ok(manager.map(|manager| Self { manager }))
    }

    /// Get all audio sessions.
    pub fn sessions(&self) -> windows::Result<Vec<AudioSession>> {
        let audio_sessions = unsafe {
            tracing::debug!("getting IAudioSessionEnumerator");
            let session_enumerator = self.manager.GetSessionEnumerator()?;

            let session_count = session_enumerator.GetCount()?;
            tracing::debug!(session_count, "got number of audio sessions");

            let mut audio_sessions = Vec::with_capacity(session_count as usize);

            for session_idx in 0..session_count {
                tracing::debug!(session_idx, "getting audio session");

                let audio_session_control = session_enumerator.GetSession(session_idx)?;
                let audio_session_control: IAudioSessionControl2 = audio_session_control.cast()?;

                audio_sessions.push(AudioSession::from(audio_session_control));
            }

            audio_sessions
        };

        Ok(audio_sessions)
    }

    /// Get events for new sessions.
    pub fn events(
        &self,
    ) -> windows::Result<(
        IAudioSessionNotification,
        Receiver<events::AudioSessionNotification>,
    )> {
        let (tx, rx) = unbounded();

        let session_events = events::AudioSessionNotifications::new(tx);

        tracing::debug!("registering session notifications");

        unsafe {
            self.manager
                .RegisterSessionNotification(session_events.clone())?;

            // Windows API requires calling GetCount before notifications will
            // be sent.
            let session_enumerator = self.manager.GetSessionEnumerator()?;
            let _session_count = session_enumerator.GetCount()?;
        }

        Ok((session_events, rx))
    }
}

/// A specific audio session.
pub struct AudioSession {
    session: IAudioSessionControl2,
    simple_audio_volume: ISimpleAudioVolume,
}

impl AudioSession {
    /// Get this audio session's process ID.
    pub fn process_id(&self) -> windows::Result<u32> {
        unsafe { self.session.GetProcessId() }
    }

    /// Get the display name for this session.
    ///
    /// This is empty for a lot of application's audio sessions.
    pub fn display_name(&self) -> windows::Result<String> {
        let display_name = unsafe {
            let display_name = self.session.GetDisplayName()?;
            pwstr_to_string(display_name)
        };

        Ok(display_name)
    }

    /// Try to collect information about the process responsible for the audio
    /// session.
    ///
    /// Some system audio sessions don't have a corresponding process or it is
    /// possible the user does not have permission to read data.
    pub fn process(&self) -> windows::Result<Option<AudioSessionProcess>> {
        let pid = self.process_id()?;

        unsafe {
            tracing::trace!(pid, "attempting to open process");
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);

            if handle.is_invalid() || handle.is_null() {
                tracing::warn!(pid, "could not open process");
                CloseHandle(handle);

                return Ok(None);
            }

            let mut buf = [0u8; 512];
            let lpfilename = PSTR(buf.as_mut_ptr());
            let nsize = buf.len() as u32;

            let written = K32GetModuleFileNameExA(handle, HINSTANCE::default(), lpfilename, nsize);
            let path = if written == 0 {
                None
            } else {
                Some(String::from_utf8_lossy(&buf[0..(written as usize)]).to_string())
            };

            let mut buf = [0u16; 512];
            let lpbasename = PWSTR(buf.as_mut_ptr());
            let nsize = buf.len() as u32;

            let written = K32GetModuleBaseNameW(handle, HINSTANCE::default(), lpbasename, nsize);
            let name = if written == 0 {
                None
            } else {
                Some(String::from_utf16_lossy(&buf[0..(written as usize)]))
            };

            CloseHandle(handle);

            Ok(Some(AudioSessionProcess { pid, path, name }))
        }
    }

    /// Register for events on session changes.
    pub fn events(
        &self,
    ) -> windows::Result<(IAudioSessionEvents, Receiver<events::AudioSessionEvent>)> {
        let (tx, rx) = unbounded();

        let session_events = events::AudioSessionEvents::new(tx);

        unsafe {
            self.session
                .RegisterAudioSessionNotification(session_events.clone())?;
        }

        Ok((session_events, rx))
    }
}

/// Information about an audio session's process.
#[derive(Debug)]
pub struct AudioSessionProcess {
    /// Process ID.
    pub pid: u32,
    /// Full path to process executable.
    pub path: Option<String>,
    /// Name of process executable.
    pub name: Option<String>,
}

impl From<IAudioSessionControl2> for AudioSession {
    fn from(audio_session_control: IAudioSessionControl2) -> Self {
        Self {
            simple_audio_volume: audio_session_control
                .cast()
                .expect("IAudioSessionControl2 could not be cast to ISimpleAudioVolume"),
            session: audio_session_control,
        }
    }
}

impl VolumeControl for AudioSession {
    fn get_volume(&mut self) -> windows::Result<f32> {
        unsafe { self.simple_audio_volume.GetMasterVolume() }
    }

    fn set_volume(&mut self, level: f32) -> windows::Result<()> {
        unsafe {
            self.simple_audio_volume
                .SetMasterVolume(level, std::ptr::null())
        }
    }

    fn get_mute(&mut self) -> windows::Result<bool> {
        unsafe { self.simple_audio_volume.GetMute() }.map(Into::into)
    }

    fn set_mute(&mut self, mute: bool) -> windows::Result<()> {
        unsafe { self.simple_audio_volume.SetMute(mute, std::ptr::null()) }
    }
}

/// Convert a PWSTR to a String by reading until a null byte is found.
unsafe fn pwstr_to_string(ptr: PWSTR) -> String {
    let mut len: usize = 0;
    let mut cursor = ptr;

    loop {
        let val = cursor.0.read();
        if val == 0 {
            break;
        }

        len += 1;
        cursor = PWSTR(cursor.0.add(1));
    }

    let slice = std::slice::from_raw_parts(ptr.0, len);
    String::from_utf16_lossy(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn init() {
        let _ = tracing_subscriber::fmt::try_init();
    }

    #[test]
    fn test_audio_session() {
        init();

        windows::initialize_mta().unwrap();

        let audio_session_manager = AudioSessionManager::new().unwrap().unwrap();

        for session in audio_session_manager.sessions().unwrap_or_default() {
            println!(
                "{} - {:?}, {:?}",
                session.process_id().unwrap(),
                session.display_name(),
                session.process()
            );
        }
    }

    #[test]
    fn test_audio_session_events() {
        init();

        windows::initialize_mta().unwrap();

        let audio_session_manager = AudioSessionManager::new().unwrap().unwrap();

        for session in audio_session_manager.sessions().unwrap_or_default() {
            if matches!(session.process(), Ok(Some(AudioSessionProcess { name, .. })) if name.as_deref() == Some("Spotify.exe"))
            {
                tracing::info!("found spotify, attempting to listen for events");
                let (_handle, events) = session.events().unwrap();

                loop {
                    match events.recv_timeout(std::time::Duration::from_secs(10)) {
                        Ok(event) => tracing::info!("got event: {:?}", event),
                        Err(_) => break,
                    }
                }
            }
        }
    }

    #[test]
    fn test_audio_session_notifications() {
        init();

        windows::initialize_mta().unwrap();

        let audio_session_manager = AudioSessionManager::new().unwrap().unwrap();

        tracing::info!("attempting to listen for notifications");
        let (_handle, events) = audio_session_manager.events().unwrap();

        loop {
            match events.recv_timeout(std::time::Duration::from_secs(10)) {
                Ok(event) => {
                    tracing::info!("got event: {:?}", event);
                }
                Err(_) => break,
            }
        }
    }

    #[test]
    fn test_get_devices() {
        init();

        windows::initialize_mta().unwrap();

        let devices = AudioDevice::active_devices().unwrap();

        for device in devices {
            println!("{:?}", device.friendly_name);
        }
    }

    #[test]
    fn test_audio_device_events() {
        init();

        windows::initialize_mta().unwrap();

        let devices = AudioDevice::active_devices().unwrap();

        for mut device in devices {
            println!("{:?}", device.friendly_name);

            if device.friendly_name.as_deref() == Some("Speakers (Realtek(R) Audio)") {
                let (_handle, events) = device.events().unwrap();

                loop {
                    match events.recv_timeout(std::time::Duration::from_secs(10)) {
                        Ok(event) => tracing::info!("got event: {:?}", event),
                        Err(_) => break,
                    }
                }
            }
        }
    }

    #[test]
    fn test_audio_device_notifications() {
        init();

        windows::initialize_mta().unwrap();

        tracing::info!("subscribing to notifications");
        let (_handle, events) = AudioDevice::notifications().unwrap();

        loop {
            match events.recv_timeout(std::time::Duration::from_secs(10)) {
                Ok(event) => tracing::info!("got event: {:?}", event),
                Err(err) => {
                    tracing::warn!("recv error: {:?}", err);
                    break;
                }
            }
        }
    }
}
